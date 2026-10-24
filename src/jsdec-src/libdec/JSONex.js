import Long from './long.js';

var json_parse = function(options) {
	"use strict";

	var at,
		ch,
		escapee = {
			'"': '"',
			'\\': '\\',
			'/': '/',
			b: '\b',
			f: '\f',
			n: '\n',
			r: '\r',
			t: '\t'
		},
		text,
		error = function(m) {

			throw {
				name: 'SyntaxError',
				message: m,
				at: at,
				text: text
			};
		},
		next = function(c) {

			if (c && c !== ch) {
				error("Expected '" + c + "' instead of '" + ch + "'");
			}

			ch = text.charAt(at);
			at += 1;
			return ch;
		},
		number = function() {

			var number,
				string = '';
			if (ch === '-') {
				string = '-';
				next('-');
			}
			while (ch >= '0' && ch <= '9') {
				string += ch;
				next();
			}
			if (ch === '.') {
				string += '.';
				while (next() && ch >= '0' && ch <= '9') {
					string += ch;
				}
			}
			if (ch === 'e' || ch === 'E') {
				string += ch;
				next();
				if (ch === '-' || ch === '+') {
					string += ch;
					next();
				}
				while (ch >= '0' && ch <= '9') {
					string += ch;
					next();
				}
			}
			number = +string;
			if (!isFinite(number)) {
				error("Bad number");
			} else {
				if (string.indexOf('.') < 0) {
					try {
						return Long.from(string, true);
					} catch (e) {
						console.log(e.message);
						console.log(e.stack);
						return string;
					}
				}
				return number;
			}
		},
		string = function() {

			var hex,
				i,
				string = '',
				uffff;

			if (ch === '"') {
				while (next()) {
					if (ch === '"') {
						next();
						return string;
					}
					if (ch === '\\') {
						next();
						if (ch === 'u') {
							uffff = 0;
							for (i = 0; i < 4; i += 1) {
								hex = parseInt(next(), 16);
								if (!isFinite(hex)) {
									break;
								}
								uffff = uffff * 16 + hex;
							}
							string += String.fromCharCode(uffff);
						} else if (typeof escapee[ch] === 'string') {
							string += escapee[ch];
						} else {
							break;
						}
					} else {
						string += ch;
					}
				}
			}
			error("Bad string");
		},
		white = function() {

			while (ch && ch <= ' ') {
				next();
			}
		},
		word = function() {

			switch (ch) {
				case 't':
					next('t');
					next('r');
					next('u');
					next('e');
					return true;
				case 'f':
					next('f');
					next('a');
					next('l');
					next('s');
					next('e');
					return false;
				case 'n':
					next('n');
					next('u');
					next('l');
					next('l');
					return null;
			}
			error("Unexpected '" + ch + "'");
		},
		value,
		array = function() {

			var array = [];
			if (ch === '[') {
				next('[');
				white();
				if (ch === ']') {
					next(']');
					return array;
				}
				while (ch) {
					array.push(value());
					white();
					if (ch === ']') {
						next(']');
						return array;
					}
					next(',');
					white();
				}
			}
			error("Bad array");
		},
		object = function() {

			var key,
				object = {};
			if (ch === '{') {
				next('{');
				white();
				if (ch === '}') {
					next('}');
					return object;
				}
				while (ch) {
					key = string();
					white();
					next(':');
					object[key] = value();
					white();
					if (ch === '}') {
						next('}');
						return object;
					}
					next(',');
					white();
				}
			}
			error("Bad object");
		};
	value = function() {

		white();
		switch (ch) {
			case '{':
				return object();
			case '[':
				return array();
			case '"':
				return string();
			case '-':
				return number();
			default:
				return ch >= '0' && ch <= '9' ? number() : word();
		}
	};

	return function(source, reviver) {
		var result;
		text = source + '';
		at = 0;
		ch = ' ';
		result = value();
		white();
		if (ch) {
			error("Syntax error");
		}

		return typeof reviver === 'function' ? (function walk(holder, key) {
			var v, value = holder[key];
			if (value && typeof value === 'object') {
				Object.keys(value).forEach(function(k) {
					v = walk(value, k);
					if (v !== undefined) {
						value[k] = v;
					} else {
						delete value[k];
					}
				});
			}
			return reviver.call(holder, key, value);
		}({
			'': result
		}, '')) : result;
	};
};

function _iterate_value(variable, pad, depth, used) {
	if (used.indexOf(variable) >= 0) {
		return null;
	}
	var spad = pad.repeat(depth);
	var nl = pad.length > 0 ? "\n" : "";
	var sp = "\"";
	var k, sval, str = "";
	var comma = false;
	if (Array.isArray(variable)) {
		used.push(variable);
		if (variable.length < 1) {
			return "[]";
		}
		str = "[" + nl;
		for (k = 0; k < variable.length; k++) {
			sval = _iterate_value(variable[k], pad, depth + 1, used);
			if (sval) {
				comma = true;
				str += spad + sval + "," + nl;
			}
		}
		if (comma) {
			str = str.slice(0, 0 - ("," + nl).length) + nl;
			str += pad.repeat(depth - 1) + "]";
		} else {
			str = str.slice(0, -1) + "]";
		}
		return str;
	} else if (["number", "bigint"].indexOf(typeof variable) >= 0) {
		return variable.toString(10);
	} else if (Long.isLong(variable)) {
		return variable.toString(10);
	} else if (typeof variable == "function") {
		return null;
	} else if (typeof variable == "object") {
		used.push(variable);
		str = "{" + nl;
		for (k in variable) {
			sval = _iterate_value(variable[k], pad, depth + 1, used);
			if (sval) {
				comma = true;
				str += spad + sp + k + sp + ":" + sval + "," + nl;
			}
		}
		if (comma) {
			str = str.slice(0, 0 - ("," + nl).length) + nl;
			str += pad.repeat(depth - 1) + "}";
		} else {
			str = str.slice(0, -1) + "}";
		}
		return str;
	} else {

		return JSON.stringify(variable);
	}
}

function stringify(variable, pad) {
	pad = pad ? pad : "";
	return _iterate_value(variable, pad, 1, []);
}

export default {
	parse: json_parse(),
	stringify: stringify
};
