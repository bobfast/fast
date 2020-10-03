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
    $(BIND)\Silver0Hook$(DETOURS_BITS).dll \
    \
!IF $(DETOURS_SOURCE_BROWSING)==1
    $(OBJD)\Silver0Hook$(DETOURS_BITS).bsc \
!ENDIF
    option

##############################################################################

dirs:
    @if not exist $(BIND) mkdir $(BIND) && echo.   Created $(BIND)
    @if not exist $(OBJD) mkdir $(OBJD) && echo.   Created $(OBJD)

$(OBJD)\Silver0Hook.obj : Silver0Hook.cpp

$(OBJD)\Silver0Hook.res : Silver0Hook.rc

$(BIND)\Silver0Hook$(DETOURS_BITS).dll $(BIND)\Silver0Hook$(DETOURS_BITS).lib: \
        $(OBJD)\Silver0Hook.obj $(OBJD)\Silver0Hook.res $(DEPS)
    cl /LD $(CFLAGS) /Fe$(@R).dll /Fd$(@R).pdb \
        $(OBJD)\Silver0Hook.obj $(OBJD)\Silver0Hook.res \
        /link $(LINKFLAGS) /subsystem:console \
        /export:DetourFinishHelperProcess,@1,NONAME \
        /export:MyNtOpenProcess \
        /export:CreateFileMappingNumaW \
        $(LIBS)

$(OBJD)\Silver0Hook$(DETOURS_BITS).bsc : $(OBJD)\Silver0Hook.obj
    bscmake /v /n /o $@ $(OBJD)\Silver0Hook.sbr


##############################################################################

clean:
    -del *~ 2>nul
    -del $(BIND)\Silver0Hook*.* 2>nul
    -rmdir /q /s $(OBJD) 2>nul

realclean: clean
    -rmdir /q /s $(OBJDS) 2>nul

############################################### Install non-bit-size binaries.

!IF "$(DETOURS_OPTION_PROCESSOR)" != ""

$(OPTD)\Silver0Hook$(DETOURS_OPTION_BITS).dll:
$(OPTD)\Silver0Hook$(DETOURS_OPTION_BITS).pdb:

$(BIND)\Silver0Hook$(DETOURS_OPTION_BITS).dll : $(OPTD)\Silver0Hook$(DETOURS_OPTION_BITS).dll
    @if exist $? copy /y $? $(BIND) >nul && echo $@ copied from $(DETOURS_OPTION_PROCESSOR).
$(BIND)\Silver0Hook$(DETOURS_OPTION_BITS).pdb : $(OPTD)\Silver0Hook$(DETOURS_OPTION_BITS).pdb
    @if exist $? copy /y $? $(BIND) >nul && echo $@ copied from $(DETOURS_OPTION_PROCESSOR).

option: \
    $(BIND)\Silver0Hook$(DETOURS_OPTION_BITS).dll \
    $(BIND)\Silver0Hook$(DETOURS_OPTION_BITS).pdb \

!ELSE

option:

!ENDIF

##############################################################################

################################################################# End of File.
