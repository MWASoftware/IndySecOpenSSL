const
  openssl_lib_info = '';

  {$IFNDEF OPENSSL_NO_MIN_VERSION}
  min_supported_ssl_version =  ((((((byte(3) shl 8) + byte(0)) shl 8) + byte (0)) shl 8) + byte(0)) shl 4; {3.0.0}
  {$ELSE}
  min_supported_ssl_version = 0;
  {$ENDIF}
  
