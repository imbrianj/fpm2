fpm2_logo = [
    'logo.png'
]

fpm2_icon = [
    'fpm2.png'
]

icon_dirs = [
  '48x48',
  '128x128',
]

i18n.merge_file(
    input: 'fpm2.metainfo.xml.in',
    output: meson.project_name() + '.metainfo.xml',
    po_dir: podir,
    type: 'xml',
    install: true,
    install_dir: join_paths(datadir, 'metainfo')
)

i18n.merge_file(
    input: 'fpm2.desktop.in',
    output: meson.project_name() + '.desktop',
    po_dir: podir,
    type: 'desktop',
    install: true,
    install_dir: join_paths(datadir, 'applications')
)

install_data(
    fpm2_logo,
    install_dir : pixmapdir
)

foreach dir: icon_dirs
    install_data(
	join_paths('icons', dir, fpm2_icon),
	install_dir: join_paths(datadir, 'icons', 'hicolor', dir, 'apps')
    )
endforeach

install_man(
    'fpm2.1'
)
