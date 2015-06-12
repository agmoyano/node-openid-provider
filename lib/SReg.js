
var options = require('./Utils.js').options;

var defaults = {
	ns: {name: 'sreg', value: 'http://openid.net/extensions/sreg/1.1'},
	consent: '', //Url to consent page
	keys: ['nickname', 'email', 'fullname', 'dob', 'gender', 'postcode', 'country', 'language', 'timezone'], //Attributes 
	dataResolver: function(key) {
		//Override this function to resolve data attributes
		//"this" resolves to SReg element
	}
};

function SReg(user_options) {
	this.config = options(defaults, user_options);
	this.permissions = {};
}

SReg.prototype.getFields = function(options) {
	var op_ns = false;
	for(var i in options) {
		if(i.substr(0, 3) == 'ns.' && options[i] == this.config.ns.value) {
			op_ns = i.substr(3);
			break;
		}
	}
	if(op_ns) {
		var self = this;
		if(!options[op_ns+'.required'] && !options[op_ns+'.optional']) {
			throw new Error("Required or optional fields must be specified.");
		}
		var fields = {};
		if(options[op_ns+'.required']) {
			options[op_ns+'.required'].split(',')
				.filter(function(key) {
					return self.config.keys.indexOf(key.trim()) !== -1;
				})
				.forEach(function(key) {
					key = key.trim();
					var data = self.config.dataResolver.call(self, key);
					if(typeof data == 'undefined' || typeof data == 'null') {
						throw new Error("Required "+key+" not present.");
					}
					fields[key] = {required: true, value: data};
				});
		}
		if(options[op_ns+'.optional']) {
			options[op_ns+'.optional'].split(',')
				.filter(function(key) {
					return self.config.keys.indexOf(key.trim()) !== -1;
				})
				.forEach(function(key) {
					key = key.trim();
					var data = self.config.dataResolver.call(self, key);
					if(typeof data == 'undefined' || typeof data == 'null') {
						return;
					}
					fields[key] = {required: false, value: data};
				});
		}
		return fields;
	}
	return false;
};

SReg.prototype.process = function(options, fields, response) {
	//We assume here that consent was given for all fields.
	var op_ns = false;
	for(var i in options) {
		if(i.substr(0, 3) == 'ns.' && options[i] == this.config.ns.value) {
			op_ns = i.substr(3);
			break;
		}
	}
	if(op_ns) {
		var ns = this.config.ns;
		response.set('openid.ns.'+ns.name, ns.value);
		for(var i in fields) {
			response.set('openid.'+ns.name+'.'+i, fields[i].value);
		}
	}
};

module.exports = SReg;
