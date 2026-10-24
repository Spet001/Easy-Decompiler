export default function() {
    this.lines = [];
    this.errors = [];
    this.log = [];

    this.printLine = function(str, offset) {
        var line = { str: str, offset: offset };
        this.lines.push(line);
    };

    this.printLog = function(str, error) {
        if (Global().evars.extra.json) {
            if(error) {
                this.errors.push(str);
            } else {
                this.log.push(str);
            }
        } else {
            console.log(str);
        }
    };

    this.macros = ['#include <stdint.h>'];

    this.addMacro = function(x) {
        if (this.macros.indexOf(x) < 0) {
            this.macros.push(x);
        }
    };

    this.printMacros = function(offset) {
        if (!Global().evars.honor.blocks) {
            var t = Global().printer.theme;
            for (var i = 0; i < this.macros.length; i++) {
                this.printLine(this.identfy() + t.macro(this.macros[i]), offset);
            }
        }
        this.printLine(this.identfy() + ' ', offset);
    };

    this.dependencies = [];

    this.addDependency = function(x) {
        if (this.dependencies.indexOf(x) < 0) {
            this.dependencies.push(x);
        }
    };

    this.printDependencies = function(offset) {
        if (Global().evars.honor.blocks) {
            return;
        }

        this.dependencies.forEach(function(x) {
            x.print(offset);
        });
        if (this.dependencies.length > 0) {
            this.printLine(this.identfy() + ' ', offset);
        }
    };

    this.identAsm = '';

    this.identAsmSet = function(size) {

        size += 10;
        while (this.identAsm.length < size) {
            this.identAsm += '    ';
        }
    };

    this.identCompare = function(size) {

        return size - ((this.identAsm.length / 4) - 10);
    };

    this.ident = '';

    this.identIn = function() {
        this.ident += '    ';
    };

    this.identOut = function(force) {
        this.ident = this.ident.substr(4, this.ident.length);
    };

    this.identfy = function(size_no_colors, string_to_print, disable_identation) {
        var ident = disable_identation ? '' : this.ident;
        if (Global().evars.honor.assembly && !Global().evars.honor.blocks) {
            string_to_print = string_to_print || '';
            size_no_colors = size_no_colors || 0;
            return '    ' + string_to_print + this.identAsm.substring(size_no_colors, this.identAsm.length) + ' | ' + ident;
        } else if (Global().evars.honor.offsets && !Global().evars.honor.blocks) {
            string_to_print = string_to_print || '';
            size_no_colors = size_no_colors || 0;
            return '    ' + string_to_print + this.identAsm.substring(size_no_colors, 14) + ' | ' + ident;
        }
        return ident;
    };
}
