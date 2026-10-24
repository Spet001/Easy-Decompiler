export default function(data) {
	this.data = data;
	this.print = function() {
		var t = Global().printer.theme;
		for (var i = 0; i < this.data.length; i++) {
			Global().context.printLine(Global().context.identfy() + t.macro(this.data[i]));
		}
	};
}
