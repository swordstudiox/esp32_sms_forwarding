idf_component_register(
  SRCS "idf_inbox.cpp"
  INCLUDE_DIRS "include"
  REQUIRES
    freertos
    idf_logbuf
    nvs_flash
)
