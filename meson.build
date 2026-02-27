project(
  'fpm2',
  'c',
  version: '0.90.2',
  license: 'GPLv2+',
  meson_version: '>= 0.56.0',
  default_options: [
    'buildtype=release',
    'warning_level=2'
  ]
)

prefix = get_option('prefix')
datadir = join_paths(prefix, get_option('datadir'))
localedir = join_paths(prefix, get_option('localedir'))
pkgdatadir = join_paths(datadir, meson.project_name())
pixmapdir = join_paths(datadir, 'pixmaps', 'fpm2')
podir = join_paths(meson.project_source_root(), 'po')

cc = meson.get_compiler('c')
pkgconfig = import('pkgconfig')
i18n = import('i18n')

glib = dependency('glib-2.0')
gtk = dependency('gtk+-3.0')
libx11 = dependency('x11')
libxml2 = dependency('libxml-2.0')
nettle = dependency('nettle')
libm = cc.find_library('m')

conf = configuration_data()

conf.set_quoted('PACKAGE_NAME', meson.project_name())
conf.set_quoted('VERSION', meson.project_version())
conf.set_quoted('GETTEXT_PACKAGE', meson.project_name())
conf.set_quoted('LOCALE_DIR', localedir)
conf.set_quoted('PACKAGE_LOCALE_DIR', localedir)
conf.set_quoted('PACKAGE_PIXMAP_DIR', pixmapdir)
conf.set10('ENABLE_NLS', true)

buildtype = get_option('buildtype')
if buildtype == 'debug'
    conf.set10('FPM_DEBUG', true)
else
    conf.set10('G_DISABLE_ASSERT', true)
    conf.set10('G_DISABLE_CHECKS', true)
endif

configure_file(
    output : 'config.h',
    configuration : conf,
    install: false
)

conf_inc = include_directories('.')

extra_cflags_check = [
  '-Wmissing-declarations',
  '-Wmissing-noreturn',
  '-Wold-style-definition',
  '-Wredundant-decls',
  '-Wpointer-arith',
  '-Wcast-align',
  '-Winit-self',
  '-Wshadow',
  '-Wmissing-include-dirs',
  '-Wundef',
  '-Wformat',
  '-Wformat-security',
  '-Wformat-y2k',
  '-Wnested-externs',
  '-Wno-unused-parameter',
  '-Wno-declaration-after-statement',
  '-Werror=implicit-function-declaration',
  '-Wno-error=deprecated-declarations',
  '-Wno-deprecated-declarations'
]

add_project_arguments('-DHAVE_CONFIG_H', language : 'c')
add_project_arguments(cc.get_supported_arguments(extra_cflags_check), language: 'c')

subdir('src')
subdir('po')
subdir('data')
