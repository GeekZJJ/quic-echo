project('quic-echo', 'c',
  version: '0.1.0',
  license: 'MIT',
)

cmake = import('cmake')

add_project_arguments(['-D_GNU_SOURCE'],
                      language: 'c')

glib_deps = [
  dependency('glib-2.0', version: '>= 2.68.2'),
]

gnutls_deps = [
  dependency('gnutls', version: '>= 3.7.2'),
]

ngtcp2_options = cmake.subproject_options()
ngtcp2_options.add_cmake_defines({
  'ENABLE_GNUTLS': true,
  'ENABLE_OPENSSL': false,
  'ENABLE_BORINGSSL': false,
})
ngtcp2_project = cmake.subproject('ngtcp2', options: ngtcp2_options)
ngtcp2_deps = [
  ngtcp2_project.dependency('ngtcp2'),
  ngtcp2_project.dependency('ngtcp2_crypto_gnutls'),
]

libutils = static_library('libutils', [
                            'connection.c',
                            'gnutls-glue.c',
                            'stream.c',
                            'utils.c',
                          ],
                          dependencies: glib_deps + gnutls_deps + ngtcp2_deps)

executable('cli', ['cli.c'],
           dependencies: glib_deps + gnutls_deps + ngtcp2_deps,
           link_with: libutils)

executable('serv', ['serv.c'],
           dependencies: glib_deps + gnutls_deps + ngtcp2_deps,
           link_with: libutils)

conf_data = configuration_data()
conf_data.set_quoted('G_LOG_DOMAIN', 'echo')
conf_data.set_quoted('GETTEXT_PACKAGE', meson.project_name())
configure_file(output : 'config.h',
               configuration : conf_data)
