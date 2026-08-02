idf_component_register(
  SRCS "idf_log.cpp" "idf_util.cpp"
  INCLUDE_DIRS "include"
  REQUIRES
    freertos
  PRIV_REQUIRES
    esp_system
    nvs_flash
)
