export default function(icj) {
	var data = {};
	icj.forEach(function(x) {
		data[x.addr.toString()] = x.classname;
	});
	this.data = data;
	this.search = function(address) {
		if (address) {
			return this.data[address.toString()];
		}
		return null;
	};
}
