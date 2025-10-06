program fpc_openssl_gui_client;

{$MODE Delphi}

uses
  Interfaces, Forms,
  TestClient in 'TestClient.pas' {Form1};

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TForm1, Form1);
  Application.Run;
end.
