idf_component_register(
  SRCS "idf_modem.cpp"
  INCLUDE_DIRS "include"
  REQUIRES
    esp_driver_gpio
    esp_driver_uart
    esp_timer
    idf_config
    idf_logbuf
    nvs_flash
    lwip
)
