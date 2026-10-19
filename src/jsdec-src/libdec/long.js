// SPDX-FileCopyrightText: 2023 Giovanni Dante Grazioli <deroad@libero.it>
// SPDX-License-Identifier: BSD-3-Clause

function to64(n, unsigned) {
	if (unsigned) {
		return BigInt.asUintN(64, n);
	}
	return BigInt.asIntN(64, n);
}

function toNum(num, unsigned) {
	const itype = typeof num;
	if (itype === 'bigint') {
		return num;
	} else if (itype === 'number') {
		const isNeg = num < 0;
		if (isNeg) {
			num = -num;
		}
		num = BigInt(num);
		if (isNeg) {
			num = 0n - num;
		}
		return BigInt.asIntN(64, num);
	} else if (Long.isLong(num)) {
		return num.value;
	}
	throw new Error("Unexpected type: " + (typeof num));
}

function Long(value, isUnsigned) {
	this.unsigned = isUnsigned;
	this.value = to64(value, isUnsigned);
	this.isLong = true;
	this.toString = function(x) { return this.value.toString(x); };
	this.add = function(x) { return new Long(this.value + toNum(x, this.unsigned), this.unsigned); };
	this.sub = function(x) { return new Long(this.value - toNum(x, this.unsigned), this.unsigned); };
	this.shl = function(x) { return new Long(this.value << toNum(x, this.unsigned), this.unsigned); };
	this.shru = function(x) { return new Long(this.value >> toNum(x, this.unsigned), this.unsigned); };
	this.and = function(x) { return new Long(this.value & toNum(x, this.unsigned), this.unsigned); };
	this.or = function(x) { return new Long(this.value | toNum(x, this.unsigned), this.unsigned); };
	this.xor = function(x) { return new Long(this.value ^ toNum(x, this.unsigned), this.unsigned); };
	this.not = function() { return new Long(!this.value, this.unsigned); };
	this.eq = function(x) { return this.value == toNum(x, this.unsigned); };
	this.ne = function(x) { return this.value != toNum(x, this.unsigned); };
	this.lt = function(x) { return this.value < toNum(x, this.unsigned); };
	this.gt = function(x) { return this.value > toNum(x, this.unsigned); };
	this.lte = function(x) { return this.value <= toNum(x, this.unsigned); };
	this.gte = function(x) { return this.value >= toNum(x, this.unsigned); };
}

Long.isLong = function(value) {
	return value && typeof value == "object" && value.isLong;
};

Long.from = function(input, isUnsigned, base) {
	const itype = typeof input;
	if (itype === 'bigint') {
		return new Long(input, isUnsigned);
	} else if (itype === 'number') {
		let value = BigInt(input);
		return new Long(value, isUnsigned);
	} else if (itype === 'string') {
		if (input.length < 1) {
			return isUnsigned ? Long.UZERO : Long.ZERO;
		}
		const isNeg = input.startsWith("-");
		if (isNeg) {
			input = input.substr(1);
		}
		if (base == 16 && !input.startsWith('0x')) {
			input = "0x" + input;
		}
		let value = BigInt(input);
		if (isNeg) {
			value = 0n - value;
		}
		return new Long(value, isUnsigned);
	} else if (Long.isLong(input)) {
		return input;
	}
	throw new Error("Invalid type for Long (" + itype + ') with args ' + [...arguments].join(', '));
};

if (typeof globalThis.Limits === 'undefined') {
	globalThis.Limits = {
		UT16_MAX: 0xFFFFn,
		UT32_MAX: 0xFFFFFFFFn,
		UT64_MAX: 0xFFFFFFFFFFFFFFFFn,
		ST16_MAX: 0x7FFFn,
		ST32_MAX: 0x7FFFFFFFn,
		ST64_MAX: 0x7FFFFFFFFFFFFFFFn,
	};
}
if (typeof globalThis.Global === 'undefined') {
	const _shared = {};
	globalThis.Global = function() { return _shared; };
}
if (typeof globalThis.rizin === 'undefined') {
	globalThis.rizin = { command: function() { return ''; }, graph: function() { return []; } };
}

Long.ZERO = Long.from(0, false);
Long.UZERO = Long.from(0, true);
Long.MAX_U64_VALUE = new Long(globalThis.Limits.UT64_MAX, true);
Long.MAX_U32_VALUE = new Long(globalThis.Limits.UT32_MAX, true);
Long.MAX_U16_VALUE = new Long(globalThis.Limits.UT16_MAX, true);
Long.MAX_S64_VALUE = new Long(globalThis.Limits.ST64_MAX, false);
Long.MAX_S32_VALUE = new Long(globalThis.Limits.ST32_MAX, false);
Long.MAX_S16_VALUE = new Long(globalThis.Limits.ST16_MAX, false);


export default Long;