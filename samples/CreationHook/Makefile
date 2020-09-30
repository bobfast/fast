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
    $(BIND)\CreationHook$(DETOURS_BITS).dll \
    \
!IF $(DETOURS_SOURCE_BROWSING)==1
    $(OBJD)\CreationHook$(DETOURS_BITS).bsc \
!ENDIF
    option

##############################################################################

dirs:
    @if not exist $(BIND) mkdir $(BIND) && echo.   Created $(BIND)
    @if not exist $(OBJD) mkdir $(OBJD) && echo.   Created $(OBJD)

$(OBJD)\CreationHook.obj : CreationHook.cpp

$(OBJD)\CreationHook.res : CreationHook.rc

$(BIND)\CreationHook$(DETOURS_BITS).dll $(BIND)\CreationHook$(DETOURS_BITS).lib: \
        $(OBJD)\CreationHook.obj $(OBJD)\CreationHook.res $(DEPS)
    cl /LD $(CFLAGS) /Fe$(@R).dll /Fd$(@R).pdb \
        $(OBJD)\CreationHook.obj $(OBJD)\CreationHook.res \
        /link $(LINKFLAGS) /subsystem:console \
        /export:DetourFinishHelperProcess,@1,NONAME \
        /export:MyNtMapViewOfSection \
        $(LIBS)

$(OBJD)\CreationHook$(DETOURS_BITS).bsc : $(OBJD)\CreationHook.obj
    bscmake /v /n /o $@ $(OBJD)\CreationHook.sbr


##############################################################################

clean:
    -del *~ 2>nul
    -del $(BIND)\CreationHook*.* 2>nul
    -rmdir /q /s $(OBJD) 2>nul

realclean: clean
    -rmdir /q /s $(OBJDS) 2>nul

############################################### Install non-bit-size binaries.

!IF "$(DETOURS_OPTION_PROCESSOR)" != ""

$(OPTD)\CreationHook$(DETOURS_OPTION_BITS).dll:
$(OPTD)\CreationHook$(DETOURS_OPTION_BITS).pdb:

$(BIND)\CreationHook$(DETOURS_OPTION_BITS).dll : $(OPTD)\CreationHook$(DETOURS_OPTION_BITS).dll
    @if exist $? copy /y $? $(BIND) >nul && echo $@ copied from $(DETOURS_OPTION_PROCESSOR).
$(BIND)\CreationHook$(DETOURS_OPTION_BITS).pdb : $(OPTD)\CreationHook$(DETOURS_OPTION_BITS).pdb
    @if exist $? copy /y $? $(BIND) >nul && echo $@ copied from $(DETOURS_OPTION_PROCESSOR).

option: \
    $(BIND)\CreationHook$(DETOURS_OPTION_BITS).dll \
    $(BIND)\CreationHook$(DETOURS_OPTION_BITS).pdb \

!ELSE

option:

!ENDIF

##############################################################################

################################################################# End of File.
