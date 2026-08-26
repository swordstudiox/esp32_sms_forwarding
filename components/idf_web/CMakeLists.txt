idf_component_register(
  SRCS "idf_web.cpp"
  INCLUDE_DIRS "include"
  REQUIRES
    app_update
    esp_partition
    espcoredump
    esp_driver_tsens
    esp_timer
    heap
    esp_http_server
    idf_config
    idf_esim
    idf_inbox
    idf_lpa
    idf_logbuf
    idf_modem
    idf_push
    idf_sms
    idf_wifi
    mbedtls
    web_assets
)
