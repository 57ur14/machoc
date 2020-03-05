# ruby-Machoc simplified
A simplified command-line interface for extracting the [Machoc hash](https://github.com/ANSSI-FR/polichombr/blob/2fa9702fca21c22b68c89a98de692ccd0fa48e1d/docs/MACHOC_HASH.md) of a PE executable using [Metasm](https://github.com/jjyg/metasm). The code is based on the [Polichombr](https://github.com/ANSSI-FR/polichombr) framework, and most of the code is directly copied from [AnalyzeIt.rb](https://github.com/ANSSI-FR/polichombr/blob/72c3d5e818100f824486a9ae48278075de3b3c39/polichombr/analysis_tools/AnalyzeIt.rb).

This script allows the extraction of a Machoc hash without needing to install or invoke the whole Polichombr framework. 

## Dependencies ##
The only dependency is Metasm, which can be installed with ``gem install metasm``

## Usage ##
``ruby ruby-machoc_simplified.rb /path/to/pe_executable.exe``

## Notice on performance ##
Extracting the Machoc hash of executables with complex code seems to be quite slow and require up to 15 seconds, but the mean execution time seems to be somewhere between  3 and 4 seconds per file (when testing on a dataset containing malicious PE32 executables).

Similar experiments using the Python+Radare2 implementation [Machoke](https://github.com/conix-security/machoke) indicate that this ruby implementation calculates Machoc hashes approximately 40 % faster.
