var Color = function(name) {
	var fn = function(x) {
		return x;
	};
	return fn;
};
Color.make = function(theme) {
	var g = {};
	for (var key in theme) {
		g[key] = Color(theme[key]);
	}
	return g;
};
export default Color;
