program fpc_openssl_gui_server;

uses
  {$IFDEF UNIX}
  cthreads,
  {$ENDIF}
  Interfaces,Forms,
  TestServer in 'TestServer.pas' {Form1};


begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TForm1, Form1);
  Application.Run;
end.
