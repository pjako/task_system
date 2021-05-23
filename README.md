# task_system (v0.1)
Fiber based task system inspired by a talk from [Christian Gyrling](https://gdcvault.com/play/1022186/Parallelizing-the-Naughty-Dog-Engine)

Uses [Tina](https://github.com/slembcke/Tina) (inlined) for the fiber creation/switching

# Features
* cross platform fiber job system (MacOS, Windows x86) (unfinished)
* [STB-style](https://github.com/nothings/stb/blob/master/docs/stb_howto.txt)
* cross-platform library for C and C++, written in C.
* no memory allocation after setup
* continue/stick tasks on specific threads.
* lockless
