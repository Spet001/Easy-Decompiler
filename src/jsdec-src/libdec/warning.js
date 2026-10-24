export default function(message) {
	if (typeof message == 'string') {
		message = "[!] " + message;
		if (this.printer.theme.comment) {
			message = this.printer.theme.comment(message);
		}
		this.context.printLog(message);
	}
}
