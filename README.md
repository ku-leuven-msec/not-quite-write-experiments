# Not Quite Write - Experiments

## Store-only bypass on SoftBound
The relevant sources are under [softbound-attack](/softbound-attack/). 
```bash
cd softbound-attack/
```

### Building SoftBound
Build the SoftBound Clang compiler in [softboundcets-llvm-clang34/](/softbound-attack/softboundcets-llvm-clang34/). 
```bash
# in softbound-attack/
mkdir install   # make directory to install SoftBound Clang to
cd softboundcets-llvm-clang34/
./configure --enable-assertions --disable-optimized --prefix=$(realpath ../install/)
make -j         # watch out with the number of parallel jobs here; building LLVM/Clang can quickly go out of memory
make install
cd ../          # back to softbound-attack dir
```

Then, build the SoftBound runtime in [softboundcets-lib](/softbound-attack/softboundcets-lib/).
```bash
# in softbound-attack/
cd softboundcets-lib/
make softboundcets_rt
cd ../
```

### Building and running the store-only attack experiments
First, build both an unprotected version of the attack and a fully-SoftBound-protected version.

```bash
make SOFTBOUND_CLANG_INSTALL=<your softbound clang install dir> SOFTBOUND_LIB_DIR=$(realpath ../softboundcets-lib/)
```

Confirm that the attack works on an unprotected binary by running 
```bash
$ ./changeage-native
What is your user ID? -1        # underflows the users array
What is your updated age? 3
Launching shell for admin:
$ 
```

> **_NOTE_**: It is not guaranteed that this offset (`-1`) will also work on your system. Dump the binary's symbols (`objdump --syms`) and look at the actual offset between the `users` array and the `adminLevel` boolean pointer. Compilation with SoftBound (both full and store-only protection) may also modify the offset again. On our system, the correct payload user ID under store-only hardening was `-13`. 

Confirm that SoftBound load+store (default) is able to stop the attack by doing the same using the `changeage-softbound` binary.
```bash
$ ./changeage-native
What is your user ID? -13       # underflows the users array
What is your updated age? 3
In LDC, base=410720, bound=410748, ptr=4106b8   # Crash! it's the load dereference check (LDC) who catches it

Softboundcets: Memory safety violation detected

Backtrace:
./changeage-softbound[0x40668b]
./changeage-softbound[0x405f1e]
./changeage-softbound[0x405462]
./changeage-softbound[0x4068eb]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf3)[0x7f2b82aa0083]
./changeage-softbound[0x404d4e]


Aborted (core dumped)
```
Now, let's try the same on a store-only hardened version. While SoftBound does include a store-only working mode, the open-source prototype does not expose this option to the clang command line interface. As such, we disable store-protection manually in [softboundcets-lib/softboundcets.h](/softbound-attack/softboundcets-lib/softboundcets.h) by unconditionally returning successfully from [`__softboundcets_spatial_load_dereference_check`](/softbound-attack/softboundcets-lib/softboundcets.h#L535), per the following change which you may apply manually:
```diff
--- a/softbound-attack/softboundcets-lib/softboundcets.h
+++ b/softbound-attack/softboundcets-lib/softboundcets.h
@@ -535,7 +535,7 @@ __WEAK_INLINE void
 __softboundcets_spatial_load_dereference_check(void *base, void *bound, 
                                                void *ptr, size_t size_of_type)
 {
-
+  return; // disable load checking -> store-only checking
   if ((ptr < base) || ((void*)((char*) ptr + size_of_type) > bound)) {
 
     __softboundcets_printf("In LDC, base=%zx, bound=%zx, ptr=%zx\n",
```

Re-build the library with 
```bash
make softboundcets_rt
```

Then re-build the attack binaries. The `changeage-softbound` binary will now effectively be store-only protected. Run the same attack again and notice how we're able to spawn the admin shell once again, as if the program was not hardened at all.  
```bash
$ ./changeage-native
What is your user ID? -13        # underflows the users array
What is your updated age? 3
Launching shell for admin:
$ 
```
