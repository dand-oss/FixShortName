declare -r SRCDIR="${r3}/FixShortName"
declare -r BUILDDIR="${SRCDIR}/build"
declare -r INSTALLDIR="${ASV_PLAT_PORTS}/FixShortName"

# rm -rf ${BUILD}

declare meth="vs"
if [ "${meth}" = 'ninja' ] ; then
    declare -a CMD=(
        cmake -GNinja -Wno-dev
        -DCMAKE_INSTALL_PREFIX="${INSTALLDIR}"
        -B "${BUILDDIR}"
        -S "${SRCDIR}"
        )
    echo "${CMD[@]}"
    "${CMD[@]}"

    # build
    cd ${BUILDDIR}
    ninja

    # run
    declare -r PROG="${BUILDDIR}/test/MemoryModulePP.exe"
    if [ -f ${PROG} ] ; then 
        echo "done"
        ${PROG}
    fi
else
    declare ARCH='-A Win32'
    if [ "${abits}" = '64' ] ; then
        ARCH='-A x64'
    fi
    declare -a CMD=(
        cmake
       	-G "Visual Studio 17 2022"
       	${ARCH}
       	-Wno-dev
        -DCMAKE_INSTALL_PREFIX="${INSTALLDIR}"
        -B "${BUILDDIR}"
        -S "${SRCDIR}"
        )
    echo "${CMD[@]}"
    "${CMD[@]}"
fi
