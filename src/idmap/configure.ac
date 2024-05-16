AC_PREREQ([2.69])

m4_include([sssd/version.m4])
AC_INIT([libsss_idmap],[VERSION_NUMBER],[sssd-devel@lists.fedorahosted.org])

AC_CONFIG_HEADERS([config.h])

AC_DEFINE_UNQUOTED(
    [SSS_ATTRIBUTE_FALLTHROUGH],
    [$sss_cv_attribute_fallthrough_val],
    [__attribute__((fallthrough)) if supported])

m4_include([sssd/src/external/sizes.m4])
m4_include([sssd/src/build_macros.m4])
m4_include([sssd/src/external/libpcre.m4])

AC_OUTPUT
