"""Add non-value static field initializer metadata to the pinned analyzer."""
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
path = root / 'blutter/src/DartField.cpp'
text = path.read_text()
old = '\t\tof << std::format("; // offset: {:#x}\\n", offset);'
new = old + '''
        if (is_static && ptr != nullptr) {
            const auto& field = dart::Field::Handle(ptr);
            const auto& initializer = dart::Function::Handle(field.InitializerFunction());
            if (!initializer.IsNull()) {
                const auto& code = dart::Code::Handle(initializer.CurrentCode());
                of << std::format("  // initializer {}: addr: {:#x}, size: {:#x}\\n",
                    name, initializer.entry_point() - DartField::cls.Library().app.base(), code.Size());
            }
        }
'''
# Access base via DartFunction's public static lib_base instead of private app linkage.
new = new.replace('DartField::cls.Library().app.base()', 'DartFnBase::GetLibBase()')
text = text.replace('#include "DartLibrary.h"', '#include "DartLibrary.h"\n#include "DartFnBase.h"')
if text.count(old) != 1:
    raise SystemExit('Unexpected analyzer source; patch not applied')
path.write_text(text.replace(old, new))

base_header = root / 'blutter/src/DartFnBase.h'
base_text = base_header.read_text()
needle = 'static void SetLibBase(intptr_t addr) { lib_base = addr; }'
if base_text.count(needle) != 1:
    raise SystemExit('Unexpected analyzer base header')
base_header.write_text(base_text.replace(needle, needle + '\n\tstatic intptr_t GetLibBase() { return lib_base; }'))
