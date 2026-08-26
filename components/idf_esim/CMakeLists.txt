idf_component_register(
  SRCS
    "idf_esim.cpp"
    "idf_esim_codec.cpp"
  INCLUDE_DIRS "include"
  REQUIRES
    idf_logbuf
    idf_modem
)
