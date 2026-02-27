fpm2_sources = [
    'main.c',
    'fpm.c',
    'fpm.h',
    'support.c',
    'support.h',
    'interface.c',
    'interface.h',
    'fpm_file.c',
    'fpm_file.h',
    'callbacks.c',
    'callbacks.h',
    'fpm_crypt.c',
    'fpm_crypt.h',
    'fpm_gpw.c',
    'fpm_gpw.h',
    'fpm_clist.c',
    'fpm_launcher.c',
    'fpm_nettle.c',
    'fpm_nettle.h'
]

fpm2 = executable(
  'fpm2',
  fpm2_sources,
  dependencies: [
    glib,
    gtk,
    libx11,
    libxml2,
    nettle,
    libm
  ],
  include_directories : conf_inc,
  install: true,
  install_dir: join_paths(prefix, get_option('bindir'))
)
