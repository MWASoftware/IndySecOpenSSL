unit TestServer;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, IdIOHandler,
  IdIOHandlerSocket, IdIOHandlerStack, IdSSL, IdSecOpenSSL, IdTCPConnection,
  IdTCPClient, IdHTTP, IdServerIOHandler, IdBaseComponent, IdComponent,
  IdCustomTCPServer, IdCustomHTTPServer, IdHTTPServer, IdSecOpenSSLX509,
  IdContext, IdGlobal;

  const
    WM_DOTEST = WM_USER;


type
  TForm1 = class(TForm)
    Memo1: TMemo;
    Button1: TButton;
    IdHTTPServer1: TIdHTTPServer;
    IdSecServerIOHandlerSSLOpenSSL1: TIdSecServerIOHandlerSSLOpenSSL;
    IdHTTP1: TIdHTTP;
    IdSecIOHandlerSocketOpenSSL1: TIdSecIOHandlerSocketOpenSSL;
    procedure Button1Click(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure FormCloseQuery(Sender: TObject; var CanClose: Boolean);
    procedure IdSecIOHandlerSocketOpenSSL1GetPassword(var Password: string);
    function IdSecIOHandlerSocketOpenSSL1VerifyPeer(Certificate: TIdX509;
      AOk: Boolean; ADepth, AError: Integer): Boolean;
    procedure IdHTTPServer1QuerySSLPort(APort: TIdPort; var VUseSSL: Boolean);
    procedure IdHTTPServer1CommandGet(AContext: TIdContext;
      ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo);
    function IdSecServerIOHandlerSSLOpenSSL1VerifyPeer(Certificate: TIdX509;
      AOk: Boolean; ADepth, AError: Integer): Boolean;
    procedure IdSecServerIOHandlerSSLOpenSSL1StatusInfo(const AMsg: string);
  private
    { Private declarations }
    FClosing: boolean;
    procedure DoTest;
    procedure OnDoTest(var Msg:TMessage); message WM_DOTEST;
    procedure ShowCertificate(Certificate : TIdX509);
    function CertificateType(Certificate: TIdX509): string;
  public
    { Public declarations }
  end;

var
  Form1: TForm1;

implementation

{$R *.dfm}

uses IdSecOpenSSLOptions;

const
  myPassword = 'mypassword';
  MyClientCertPackage = '..\certs\myclient.p12';
  LineEnding = #$0D#$0A;
  remoteSource = 'https://localhost:8080/openssltest.txt';
  sGetException = 'Error: Status = %d returned when GETting %s';


type
  TResponseTextBuffer = class(TMemoryStream)
  private
    function GetDataString: AnsiString;
  public
    property DataString: AnsiString read GetDataString;
  end;


procedure TForm1.Button1Click(Sender: TObject);
begin
  Close
end;

function TForm1.CertificateType(Certificate: TIdX509): string;
begin
  if Certificate.Issuer.Hash.C1 = Certificate.Subject.Hash.C1 then
    Result := 'Root'
  else
    Result := 'Remote';
end;

procedure TForm1.DoTest;
var ResponseStream: TResponseTextBuffer;
begin
  ResponseStream := TResponseTextBuffer.Create;
  try
    IdHTTP1.Get(remoteSource,ResponseStream);
    Memo1.Lines.Add('Using SSL/TLS Version ' + IdSecIOHandlerSocketOpenSSL1.SSLSocket.SSLProtocolVersionStr+ ' with cipher '+
                                           IdSecIOHandlerSocketOpenSSL1.SSLSocket.Cipher.Name);
    if IdHTTP1.ResponseCode = 200 then
    begin
      Memo1.Lines.Add('Remote Source returned:');
      Memo1.Lines.Add(ResponseStream.DataString);
    end
    else
      Memo1.Lines.Add(Format(sGetException,[IdHTTP1.ResponseCode,remoteSource]));
  finally
    ResponseStream.Free;
  end;
end;

procedure TForm1.FormCloseQuery(Sender: TObject; var CanClose: Boolean);
begin
  FClosing := true;
  CanClose := true;
end;

procedure TForm1.FormShow(Sender: TObject);
begin
  Memo1.Lines.Clear;
  PostMessage(self.Handle,WM_DOTEST,0,0);
end;

procedure TForm1.IdHTTPServer1CommandGet(AContext: TIdContext;
  ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo);
var S: TStringStream;
begin
  S := TStringStream.Create('Server Response' + LineEnding);
  S.WriteString('Command: ' + ARequestInfo.RawHTTPCommand + LineEnding);
  S.WriteString('Remote IP: ' + ARequestInfo.RemoteIP + LineEnding);
  S.WriteString('Success!' + LineEnding);
  AResponseInfo.ContentStream := S;
  AResponseInfo.ContentType := 'text/html';
  AResponseInfo.ContentEncoding := 'UTF-8';
  AResponseInfo.CharSet := 'UTF-8';
  AResponseInfo.CloseConnection := true;
  AResponseInfo.ContentStream.Position := 0;
end;

procedure TForm1.IdHTTPServer1QuerySSLPort(APort: TIdPort;
  var VUseSSL: Boolean);
begin
  VUseSSL := (APort = 8080);
end;

procedure TForm1.IdSecIOHandlerSocketOpenSSL1GetPassword(var Password: string);
begin
  Password := myPassword;
end;

function TForm1.IdSecIOHandlerSocketOpenSSL1VerifyPeer(Certificate: TIdX509;
  AOk: Boolean; ADepth, AError: Integer): Boolean;
begin
  Memo1.Lines.Add('');
  Memo1.Lines.Add('Client Side Verification');
  if AOK then
   Memo1.Lines.Add(CertificateType(Certificate)+' Certificate verification succeeded')
  else
   Memo1.Lines.Add(CertificateType(Certificate)+' Certificate verification failed');
  ShowCertificate(certificate);
  Result := AOK;
end;

procedure TForm1.IdSecServerIOHandlerSSLOpenSSL1StatusInfo(const AMsg: string);
begin
  Memo1.Lines.Add('Server Status Info: '+AMsg);
end;

function TForm1.IdSecServerIOHandlerSSLOpenSSL1VerifyPeer(Certificate: TIdX509;
  AOk: Boolean; ADepth, AError: Integer): Boolean;
begin
  Memo1.Lines.Add('');
  Memo1.Lines.Add('Server Side Verification');
  if AOK then
   Memo1.Lines.Add(CertificateType(Certificate)+' Certificate verification succeeded')
  else
   Memo1.Lines.Add(CertificateType(Certificate)+' Certificate verification failed');
  ShowCertificate(certificate);
  Result := AOK;
end;

procedure TForm1.OnDoTest(var Msg: TMessage);
begin
  IdHTTPServer1.Active := true;
  DoTest;
  IdHTTPServer1.Active := false;
  IdSecIOHandlerSocketOpenSSL1.Close;

  {Update SSL Options for client verification}
  with IdSecIOHandlerSocketOpenSSL1 do
  begin
    SSLOptions.CertFile := MyClientCertPackage;
    SSLOptions.KeyFile := MyClientCertPackage;
  end;
  with IdSecServerIOHandlerSSLOpenSSL1 do
  begin
    SSLOptions.VerifyMode := [sslvrfPeer,sslvrfFailIfNoPeerCert];
    SSLOptions.VerifyDirs := '..\cacerts';
  end;
  IdHTTPServer1.Active := true;
  DoTest;
  IdHTTPServer1.Active := false;
  IdSecIOHandlerSocketOpenSSL1.Close;
end;

procedure TForm1.ShowCertificate(Certificate: TIdX509);
begin
  Memo1.Lines.Add('');
  Memo1.Lines.Add('X.509 Certificate Details');
  Memo1.Lines.Add('Subject: '+ Certificate.Subject.OneLine);
  Memo1.Lines.Add('Issuer: '+ Certificate.Issuer.OneLine);
  Memo1.Lines.Add('Not Before: '+DateTimeToStr(Certificate.notBefore));
  Memo1.Lines.Add('Not After: '+DateTimeToStr(Certificate.notAfter));
  Memo1.Lines.Add('');
end;

{ TResponseTextBuffer }

function TResponseTextBuffer.GetDataString: AnsiString;
begin
  SetLength(Result,Size);
  Position := 0;
  Read(Result[1],Size);
  SetCodePage(RawByteString(Result), DefaultSystemCodePage, False);
end;

end.
