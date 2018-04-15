/* 
 * backtrace() and backtrace_symbols() for mingw64 v5
 * Compile: -I %MINGW_HOME%/include -lDbgHelp -lbfd -liberty -lz 
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#ifndef PACKAGE
#define PACKAGE "mingw64-backtrace"
#define PACKAGE_VERSION "0.1"
#endif
#include <bfd.h>
#include <windows.h>
#include <DbgHelp.h>

static int
cmpbfdsymvals(const void *ppsym1, const void *ppsym2) {
  return bfd_asymbol_value(*(asymbol **)ppsym1)
    - bfd_asymbol_value(*(asymbol **)ppsym2);
}

int
backtrace(void **btaddrs, int nbtaddrs) {
  return RtlCaptureStackBackTrace(1, nbtaddrs, btaddrs, 0);
}

char **
backtrace_symbols(void **btaddrs, int nbtaddrs) {
  HANDLE process = GetCurrentProcess();
  SymInitialize(process, NULL, TRUE);

  /* read all symbols from bfd, filter and sort them by val */
  bfd_init();
  bfd *bfd = bfd_openr(_pgmptr, NULL);
  if(!bfd) {
    bfd_perror("bfd_openr");
    exit(-1);
  }
  if(!bfd_check_format(bfd, bfd_object)) {
    bfd_perror("bfd_check_format");
    exit(-1);
  }
  long bfdsymtabsize = bfd_get_symtab_upper_bound(bfd);
  if(bfdsymtabsize < 0) {
    bfd_perror("bfd_get_symtab_upper_bound");
    exit(-1);
  }
  if(bfdsymtabsize == 0) {
    printf("no symbols\n"); // TODO
    exit(0);
  }
  asymbol **bfdsyms = (asymbol **)malloc(bfdsymtabsize);
  assert(bfdsyms);
  long nbfdsyms = bfd_canonicalize_symtab(bfd, bfdsyms);
  if(nbfdsyms < 0) {
    bfd_perror("bfd_canonicalize_symtab");
    exit(-1);
  }
  /* keep only ptrs to fun syms */
  int i, lastfunsym = 0;
  for(i = 0; i < nbfdsyms; i++) {
    asymbol *bfdsym = bfdsyms[i];
    int symclass = bfd_decode_symclass(bfdsym);
    if('t' == symclass || 'T' == symclass)
      bfdsyms[lastfunsym++] = bfdsyms[i];
  }
  qsort(bfdsyms, lastfunsym, sizeof(asymbol *), cmpbfdsymvals);

  /* find backtrace symbols and sum name lengths */
  asymbol **btsyms = (asymbol **)malloc(nbtaddrs * sizeof(asymbol *));
  assert(btsyms);
  int btsymnameslen = 0;
  char winsymbuf[sizeof(SYMBOL_INFO)+ MAX_SYM_NAME * sizeof(TCHAR)];
  PSYMBOL_INFO winsym = (PSYMBOL_INFO)winsymbuf;
  winsym->SizeOfStruct = sizeof(SYMBOL_INFO);
  winsym->MaxNameLen = MAX_SYM_NAME;
  DWORD64 displ;
  for(i = 0; i < nbtaddrs; i++) {
    void *btaddr = btaddrs[i];
    btsyms[i] = 0;
    /* try Windows */
    if(SymFromAddr(process, (DWORD64)btaddr, &displ, winsym)) {
      btsymnameslen += strlen(winsym->Name) + 1;
      continue;
    }
    /* try bfdsyms */
    int lo = 0, hi = lastfunsym - 1;
    while(lo < hi) {
      int mid = (hi + lo) / 2;
      asymbol *midsym = bfdsyms[mid];
      void *midsymval = (void *)bfd_asymbol_value(midsym);
      asymbol *nextsym = bfdsyms[mid + 1];
      void *nextsymval = (void *)bfd_asymbol_value(nextsym);
      if(midsymval <= btaddr && btaddr <= nextsymval) {
	btsyms[i] = midsym;
	btsymnameslen += strlen(bfd_asymbol_name(midsym)) + 1;
	break;
      } else if(btaddr < midsymval) {
	assert(btaddr < nextsymval);
	hi = mid;
	continue;
      } else {
	assert(nextsymval < btaddr);
	lo = mid + 1;
	continue;
      }
    }
    if(lo < hi) /* found */
      continue;
    /* will use address */
    btsymnameslen += 18;
  }

  /* put bt sym names ptrs and contents into return buf */
  char **btsymnames = (char **)malloc
    ((nbtaddrs + 1) * sizeof(char *) + btsymnameslen);
  assert(btsymnames);
  char *btsymnamecontents = (char *)(btsymnames + nbtaddrs + 1);
  for(i = 0; i < nbtaddrs; i++) {
    if(btsyms[i])
      strcpy(btsymnamecontents, bfd_asymbol_name(btsyms[i]));
    else {
      if(SymFromAddr(process, (DWORD64)btaddrs[i], &displ, winsym))
	strcpy(btsymnamecontents, winsym->Name);
      else 
	sprintf(btsymnamecontents, "%p", btaddrs[i]);
    }
    btsymnames[i] = btsymnamecontents;
    btsymnamecontents += strlen(btsymnamecontents) + 1;
  }
  btsymnames[nbtaddrs] = 0;
  free(btsyms);
  free(bfdsyms);
  bfd_close(bfd);
  SymCleanup(process);
  return btsymnames;
}


