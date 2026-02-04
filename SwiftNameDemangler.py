#Demangles Swift class, function, and variable names (Optimized)
#@author LaurieWired (original), optimized for batch processing
#@category Swift

# NOTES:
# Requires Swift to be installed on the machine
# Batch processes all symbols through a single swift demangle process

from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import SymbolType, SourceType
from ghidra.program.model.listing import CodeUnit
from java.lang import System
import subprocess

def batch_demangle(names):
    """Demangle a list of names in one shot via stdin pipe"""
    if not names:
        return []

    os_name = System.getProperty("os.name").lower()
    if "mac" in os_name:
        cmd = 'xcrun swift-demangle --simplified --compact'
    else:
        cmd = 'swift demangle --simplified --compact'

    input_text = "\n".join(names).encode('utf-8')

    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate(input_text)

    results = stdout.decode('utf-8').strip().split("\n")

    # Clean up "mangled ---> demangled" format if present
    cleaned_results = []
    for r in results:
        if ' ---> ' in r:
            cleaned_results.append(r.split(' ---> ')[-1].strip())
        else:
            cleaned_results.append(r.strip())

    # Pad results if mismatch
    while len(cleaned_results) < len(names):
        cleaned_results.append(names[len(cleaned_results)])

    return cleaned_results

def clean_demangled_name(name):
    name = name.split("(")[0]
    name = name.replace(" ", "_")
    name = name.replace("<", "_")
    name = name.replace(">", "_")
    return name

def beautify_swift_program():
    BATCH_SIZE = 500

    # === Phase 1: Functions ===
    print("Collecting functions...")
    funcs = []
    func_names = []
    for func in currentProgram.getFunctionManager().getFunctions(True):
        funcs.append(func)
        func_names.append(func.getName())

    print("Demangling {} functions...".format(len(func_names)))
    renamed_count = 0

    for i in range(0, len(func_names), BATCH_SIZE):
        batch_names = func_names[i:i+BATCH_SIZE]
        batch_funcs = funcs[i:i+BATCH_SIZE]
        demangled_list = batch_demangle(batch_names)

        for func, original, demangled in zip(batch_funcs, batch_names, demangled_list):
            cleaned = clean_demangled_name(demangled)
            if not cleaned or cleaned == original:
                continue
            func.setComment("Original: {}\nDemangled: {}".format(original, demangled))
            func.setName(cleaned, SourceType.USER_DEFINED)
            renamed_count += 1

        print("  processed {}/{}".format(min(i+BATCH_SIZE, len(func_names)), len(func_names)))

    print("Functions renamed: {}".format(renamed_count))

    # === Phase 2: Labels ===
    print("\nCollecting labels...")
    labels = []
    label_names = []
    for symbol in currentProgram.getSymbolTable().getAllSymbols(True):
        if symbol.getSymbolType() == SymbolType.LABEL:
            labels.append(symbol)
            label_names.append(symbol.getName())

    print("Demangling {} labels...".format(len(label_names)))
    renamed_count = 0

    for i in range(0, len(label_names), BATCH_SIZE):
        batch_names = label_names[i:i+BATCH_SIZE]
        batch_labels = labels[i:i+BATCH_SIZE]
        demangled_list = batch_demangle(batch_names)

        for symbol, original, demangled in zip(batch_labels, batch_names, demangled_list):
            cleaned = clean_demangled_name(demangled)
            if not cleaned or cleaned == original:
                continue
            currentProgram.getListing().setComment(symbol.getAddress(), CodeUnit.EOL_COMMENT, "Original: {}\nDemangled: {}".format(original, demangled))
            symbol.setName(cleaned, SourceType.USER_DEFINED)
            renamed_count += 1

        print("  processed {}/{}".format(min(i+BATCH_SIZE, len(label_names)), len(label_names)))

    print("Labels renamed: {}".format(renamed_count))
    print("\nDone!")

beautify_swift_program()