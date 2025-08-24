import React, { useState, useCallback } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Checkbox } from "@/components/ui/checkbox";
import { useToast } from "@/hooks/use-toast";
import { Upload, Settings, Download, Loader2, Shield, Network } from "lucide-react";

interface FormData {
  file: File | null;
  target: 'firewall' | 'panorama';
  templateName: string;
  outputInterface: string;
  localIpAddress: string;
  securityZone: 'yes' | 'no';
  zoneName: string;
  routing: 'none' | 'virtual' | 'logical';
  routerName: string;
  convertLocalRemoteId: boolean;
  convertProxyId: boolean;
  convertTunnelMonitor: boolean;
}

export const ConverterForm = () => {
  const { toast } = useToast();
  const [formData, setFormData] = useState<FormData>({
    file: null,
    target: 'firewall',
    templateName: '',
    outputInterface: '',
    localIpAddress: '',
    securityZone: 'no',
    zoneName: '',
    routing: 'none',
    routerName: '',
    convertLocalRemoteId: true,
    convertProxyId: true,
    convertTunnelMonitor: false,
  });
  const [isProcessing, setIsProcessing] = useState(false);
  const [dragActive, setDragActive] = useState(false);

  const handleDrag = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    const files = e.dataTransfer.files;
    if (files && files[0]) {
      const file = files[0];
      if (file.name.endsWith('.txt')) {
        setFormData(prev => ({ ...prev, file }));
        toast({
          title: "Arquivo carregado",
          description: `${file.name} foi selecionado com sucesso.`
        });
      } else {
        toast({
          title: "Erro no arquivo",
          description: "Por favor, selecione apenas arquivos .txt",
          variant: "destructive"
        });
      }
    }
  }, [toast]);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setFormData(prev => ({ ...prev, file }));
      toast({
        title: "Arquivo carregado",
        description: `${file.name} foi selecionado com sucesso.`
      });
    }
  };

  const isFormValid = () => {
    if (!formData.file) return false;
    if (!formData.outputInterface || !formData.localIpAddress) return false;
    if (formData.target === 'panorama' && !formData.templateName) return false;
    if (formData.securityZone === 'yes' && !formData.zoneName) return false;
    if (formData.routing !== 'none' && !formData.routerName) return false;
    return true;
  };

  const handleSubmit = async () => {
    if (!isFormValid()) return;

    setIsProcessing(true);
    
    try {
      const formDataToSend = new FormData();
      formDataToSend.append('file', formData.file!);
      formDataToSend.append('target', formData.target);
      if (formData.target === 'panorama') {
        formDataToSend.append('template_name', formData.templateName);
      }
      formDataToSend.append('output_interface', formData.outputInterface);
      formDataToSend.append('local_ip_address', formData.localIpAddress);
      formDataToSend.append('security_zone', formData.securityZone);
      if (formData.securityZone === 'yes') {
        formDataToSend.append('zone_name', formData.zoneName);
      }
      formDataToSend.append('routing', formData.routing);
      if (formData.routing !== 'none') {
        formDataToSend.append('router_name', formData.routerName);
      }
      formDataToSend.append('convert_local_remote_id', formData.convertLocalRemoteId.toString());
      formDataToSend.append('convert_proxy_id', formData.convertProxyId.toString());
      formDataToSend.append('convert_tunnel_monitor', formData.convertTunnelMonitor.toString());

      const response = await fetch('/functions/v1/process-config', {
        method: 'POST',
        body: formDataToSend,
      });

      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'palo_alto_configs.zip';
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
        
        toast({
          title: "Conversão concluída!",
          description: "O arquivo foi baixado com sucesso."
        });
      } else {
        const errorData = await response.json();
        toast({
          title: "Erro na conversão",
          description: errorData.error || "Erro desconhecido",
          variant: "destructive"
        });
      }
    } catch (error) {
      toast({
        title: "Erro de conexão",
        description: "Não foi possível conectar ao servidor",
        variant: "destructive"
      });
    } finally {
      setIsProcessing(false);
    }
  };

  return (
    <div className="min-h-screen bg-background">
      <div className="container mx-auto px-4 py-8">
        {/* Header */}
        <div className="text-center mb-12">
          <div className="flex items-center justify-center gap-3 mb-4">
            <Network className="h-8 w-8 text-primary" />
            <h1 className="text-4xl font-bold bg-gradient-to-r from-primary to-accent bg-clip-text text-transparent">
              Conversor de Túneis IPsec
            </h1>
            <Shield className="h-8 w-8 text-primary" />
          </div>
          <p className="text-xl text-muted-foreground">
            Juniper SRX → Palo Alto Networks
          </p>
          <p className="text-sm text-muted-foreground mt-2">
            Converta facilmente suas configurações de túneis IPsec entre plataformas
          </p>
        </div>

        <div className="max-w-4xl mx-auto space-y-8">
          {/* Step 1: File Upload */}
          <Card className="border-border bg-card shadow-lg">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Upload className="h-5 w-5 text-primary" />
                Passo 1: Upload do Arquivo
              </CardTitle>
              <CardDescription>
                Selecione o arquivo de configuração Juniper (.txt)
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div
                className={`border-2 border-dashed rounded-lg p-8 text-center transition-colors ${
                  dragActive 
                    ? 'border-primary bg-primary/10' 
                    : 'border-border hover:border-primary/50'
                }`}
                onDragEnter={handleDrag}
                onDragLeave={handleDrag}
                onDragOver={handleDrag}
                onDrop={handleDrop}
              >
                <Upload className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                <p className="text-lg font-medium mb-2">
                  {formData.file ? formData.file.name : 'Arraste e solte seu arquivo aqui'}
                </p>
                <p className="text-muted-foreground mb-4">ou</p>
                <Input
                  type="file"
                  accept=".txt"
                  onChange={handleFileChange}
                  className="hidden"
                  id="file-upload"
                />
                <Label htmlFor="file-upload">
                  <Button variant="secondary" className="cursor-pointer" asChild>
                    <span>Selecionar Arquivo</span>
                  </Button>
                </Label>
              </div>
            </CardContent>
          </Card>

          {/* Step 2: Configuration Parameters */}
          <Card className="border-border bg-card shadow-lg">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Settings className="h-5 w-5 text-primary" />
                Passo 2: Parâmetros de Destino
              </CardTitle>
              <CardDescription>
                Configure os parâmetros para a conversão
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Target Configuration */}
              <div className="space-y-3">
                <Label className="text-base font-medium">Alvo da Configuração</Label>
                <RadioGroup
                  value={formData.target}
                  onValueChange={(value: 'firewall' | 'panorama') =>
                    setFormData(prev => ({ ...prev, target: value, templateName: '' }))
                  }
                  className="flex gap-6"
                >
                  <div className="flex items-center space-x-2">
                    <RadioGroupItem value="firewall" id="firewall" />
                    <Label htmlFor="firewall">Firewall</Label>
                  </div>
                  <div className="flex items-center space-x-2">
                    <RadioGroupItem value="panorama" id="panorama" />
                    <Label htmlFor="panorama">Panorama</Label>
                  </div>
                </RadioGroup>
                {formData.target === 'panorama' && (
                  <div className="ml-6">
                    <Label htmlFor="template-name">Nome do Template</Label>
                    <Input
                      id="template-name"
                      value={formData.templateName}
                      onChange={(e) => setFormData(prev => ({ ...prev, templateName: e.target.value }))}
                      placeholder="Digite o nome do template"
                    />
                  </div>
                )}
              </div>

              {/* Local Interface */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="output-interface">Interface de Saída</Label>
                  <Input
                    id="output-interface"
                    value={formData.outputInterface}
                    onChange={(e) => setFormData(prev => ({ ...prev, outputInterface: e.target.value }))}
                    placeholder="Ex: ethernet1/1"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="local-ip">Endereço IP Local</Label>
                  <Input
                    id="local-ip"
                    value={formData.localIpAddress}
                    onChange={(e) => setFormData(prev => ({ ...prev, localIpAddress: e.target.value }))}
                    placeholder="Ex: 192.168.1.1"
                  />
                </div>
              </div>

              {/* Security Zone */}
              <div className="space-y-3">
                <Label className="text-base font-medium">Security Zone</Label>
                <RadioGroup
                  value={formData.securityZone}
                  onValueChange={(value: 'yes' | 'no') =>
                    setFormData(prev => ({ ...prev, securityZone: value, zoneName: '' }))
                  }
                  className="flex gap-6"
                >
                  <div className="flex items-center space-x-2">
                    <RadioGroupItem value="no" id="zone-no" />
                    <Label htmlFor="zone-no">Não</Label>
                  </div>
                  <div className="flex items-center space-x-2">
                    <RadioGroupItem value="yes" id="zone-yes" />
                    <Label htmlFor="zone-yes">Sim</Label>
                  </div>
                </RadioGroup>
                {formData.securityZone === 'yes' && (
                  <div className="ml-6">
                    <Label htmlFor="zone-name">Nome da Zona</Label>
                    <Input
                      id="zone-name"
                      value={formData.zoneName}
                      onChange={(e) => setFormData(prev => ({ ...prev, zoneName: e.target.value }))}
                      placeholder="Digite o nome da zona"
                    />
                  </div>
                )}
              </div>

              {/* Routing */}
              <div className="space-y-3">
                <Label className="text-base font-medium">Roteamento</Label>
                <RadioGroup
                  value={formData.routing}
                  onValueChange={(value: 'none' | 'virtual' | 'logical') =>
                    setFormData(prev => ({ ...prev, routing: value, routerName: '' }))
                  }
                  className="flex gap-6"
                >
                  <div className="flex items-center space-x-2">
                    <RadioGroupItem value="none" id="routing-none" />
                    <Label htmlFor="routing-none">Não Definir</Label>
                  </div>
                  <div className="flex items-center space-x-2">
                    <RadioGroupItem value="virtual" id="routing-virtual" />
                    <Label htmlFor="routing-virtual">Virtual Router</Label>
                  </div>
                  <div className="flex items-center space-x-2">
                    <RadioGroupItem value="logical" id="routing-logical" />
                    <Label htmlFor="routing-logical">Logical Router</Label>
                  </div>
                </RadioGroup>
                {formData.routing !== 'none' && (
                  <div className="ml-6">
                    <Label htmlFor="router-name">Nome do Roteador</Label>
                    <Input
                      id="router-name"
                      value={formData.routerName}
                      onChange={(e) => setFormData(prev => ({ ...prev, routerName: e.target.value }))}
                      placeholder="Digite o nome do roteador"
                    />
                  </div>
                )}
              </div>

              {/* Conversion Options */}
              <div className="space-y-3">
                <Label className="text-base font-medium">Opções de Conversão</Label>
                <div className="space-y-3">
                  <div className="flex items-center space-x-2">
                    <Checkbox
                      id="convert-local-remote"
                      checked={formData.convertLocalRemoteId}
                      onCheckedChange={(checked) =>
                        setFormData(prev => ({ ...prev, convertLocalRemoteId: !!checked }))
                      }
                    />
                    <Label htmlFor="convert-local-remote">Converter Local/Remote ID</Label>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Checkbox
                      id="convert-proxy"
                      checked={formData.convertProxyId}
                      onCheckedChange={(checked) =>
                        setFormData(prev => ({ ...prev, convertProxyId: !!checked }))
                      }
                    />
                    <Label htmlFor="convert-proxy">Converter Proxy ID</Label>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Checkbox
                      id="convert-tunnel"
                      checked={formData.convertTunnelMonitor}
                      onCheckedChange={(checked) =>
                        setFormData(prev => ({ ...prev, convertTunnelMonitor: !!checked }))
                      }
                    />
                    <Label htmlFor="convert-tunnel">Converter Tunnel Monitor</Label>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Step 3: Convert and Download */}
          <Card className="border-border bg-card shadow-lg">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Download className="h-5 w-5 text-primary" />
                Passo 3: Converter e Baixar
              </CardTitle>
              <CardDescription>
                Execute a conversão e baixe o arquivo resultante
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Button
                onClick={handleSubmit}
                disabled={!isFormValid() || isProcessing}
                className="w-full md:w-auto bg-gradient-to-r from-primary to-accent hover:from-primary/90 hover:to-accent/90 text-primary-foreground font-semibold py-3 px-8"
                size="lg"
              >
                {isProcessing ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Processando...
                  </>
                ) : (
                  <>
                    <Download className="mr-2 h-4 w-4" />
                    Converter e Fazer Download
                  </>
                )}
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
};