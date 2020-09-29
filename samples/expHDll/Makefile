##############################################################################
##
##  API Extention to Measure time slept.
##
##  Microsoft Research Detours Package
##
##  Copyright (c) Microsoft Corporation.  All rights reserved.
##

!include ..\common.mak

LIBS=$(LIBS) kernel32.lib

##############################################################################

all: dirs \
    $(BIND)\expHDll$(DETOURS_BITS).dll \
    \
!IF $(DETOURS_SOURCE_BROWSING)==1
    $(OBJD)\expHDll$(DETOURS_BITS).bsc \
!ENDIF
    option

##############################################################################

dirs:
    @if not exist $(BIND) mkdir $(BIND) && echo.   Created $(BIND)
    @if not exist $(OBJD) mkdir $(OBJD) && echo.   Created $(OBJD)

$(OBJD)\expHDll.obj : expHDll.cpp

$(OBJD)\expHDll.res : expHDll.rc

$(BIND)\expHDll$(DETOURS_BITS).dll $(BIND)\expHDll$(DETOURS_BITS).lib: \
        $(OBJD)\expHDll.obj $(OBJD)\expHDll.res $(DEPS)
    cl /LD $(CFLAGS) /Fe$(@R).dll /Fd$(@R).pdb \
        $(OBJD)\expHDll.obj $(OBJD)\expHDll.res \
        /link $(LINKFLAGS) /subsystem:console \
        /export:DetourFinishHelperProcess,@1,NONAME \
        /export:MyCreateProcessInternalA \
        /export:HookCreateProcessA \
        /export:HookCreateProcessW \
        $(LIBS)

$(OBJD)\expHDll$(DETOURS_BITS).bsc : $(OBJD)\expHDll.obj
    bscmake /v /n /o $@ $(OBJD)\expHDll.sbr


##############################################################################

clean:
    -del *~ 2>nul
    -del $(BIND)\expHDll*.* 2>nul
    -rmdir /q /s $(OBJD) 2>nul

realclean: clean
    -rmdir /q /s $(OBJDS) 2>nul

############################################### Install non-bit-size binaries.

!IF "$(DETOURS_OPTION_PROCESSOR)" != ""

$(OPTD)\expHDll$(DETOURS_OPTION_BITS).dll:
$(OPTD)\expHDll$(DETOURS_OPTION_BITS).pdb:

$(BIND)\expHDll$(DETOURS_OPTION_BITS).dll : $(OPTD)\expHDll$(DETOURS_OPTION_BITS).dll
    @if exist $? copy /y $? $(BIND) >nul && echo $@ copied from $(DETOURS_OPTION_PROCESSOR).
$(BIND)\expHDll$(DETOURS_OPTION_BITS).pdb : $(OPTD)\expHDll$(DETOURS_OPTION_BITS).pdb
    @if exist $? copy /y $? $(BIND) >nul && echo $@ copied from $(DETOURS_OPTION_PROCESSOR).

option: \
    $(BIND)\expHDll$(DETOURS_OPTION_BITS).dll \
    $(BIND)\expHDll$(DETOURS_OPTION_BITS).pdb \

!ELSE

option:

!ENDIF

##############################################################################

################################################################# End of File.
