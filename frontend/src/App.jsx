import React, { useState } from 'react';
import { Shield, Search, AlertTriangle, CheckCircle, XCircle } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';

const API_URL = 'http://localhost:8000';

function App() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState([]);

  const checkURL = async () => {
    if (!url.trim()) {
      alert('Por favor, insira uma URL válida');
      return;
    }

    setLoading(true);
    try {
      const response = await fetch(`${API_URL}/api/check-url`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: url.trim() }),
      });

      if (!response.ok) {
        throw new Error('Erro ao verificar URL');
      }

      const data = await response.json();
      setResults([data, ...results]);
      setUrl('');
    } catch (error) {
      console.error('Erro:', error);
      alert('Erro ao verificar URL. Verifique se o backend está rodando.');
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    checkURL();
  };

  const getRiskIcon = (riskLevel) => {
    switch (riskLevel) {
      case 'safe':
        return <CheckCircle className="h-5 w-5 text-green-500" />;
      case 'suspicious':
        return <AlertTriangle className="h-5 w-5 text-yellow-500" />;
      case 'malicious':
        return <XCircle className="h-5 w-5 text-red-500" />;
      default:
        return null;
    }
  };

  const getRiskColor = (riskLevel) => {
    switch (riskLevel) {
      case 'safe':
        return 'bg-green-100 text-green-800 border-green-200';
      case 'suspicious':
        return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'malicious':
        return 'bg-red-100 text-red-800 border-red-200';
      default:
        return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const getRiskText = (riskLevel) => {
    switch (riskLevel) {
      case 'safe':
        return 'Segura';
      case 'suspicious':
        return 'Suspeita';
      case 'malicious':
        return 'Maliciosa';
      default:
        return 'Desconhecido';
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100">
      <div className="container mx-auto px-4 py-8">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center gap-3 mb-4">
            <Shield className="h-12 w-12 text-blue-600" />
            <h1 className="text-4xl font-bold text-gray-900">Phishing Detector</h1>
          </div>
          <p className="text-gray-600 text-lg">
            Verifique URLs suspeitas e proteja-se contra phishing
          </p>
        </div>

        {/* URL Input Card */}
        <Card className="mb-8 max-w-3xl mx-auto">
          <CardHeader>
            <CardTitle>Verificar URL</CardTitle>
            <CardDescription>
              Insira a URL que deseja verificar abaixo
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="flex gap-2">
              <Input
                type="text"
                placeholder="https://exemplo.com"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                className="flex-1"
                disabled={loading}
              />
              <Button type="submit" disabled={loading}>
                {loading ? (
                  <>
                    <span className="animate-spin mr-2">⏳</span>
                    Verificando...
                  </>
                ) : (
                  <>
                    <Search className="h-4 w-4 mr-2" />
                    Verificar
                  </>
                )}
              </Button>
            </form>
          </CardContent>
        </Card>

        {/* Results Section */}
        {results.length > 0 && (
          <div className="max-w-6xl mx-auto">
            <h2 className="text-2xl font-bold text-gray-900 mb-4">
              Resultados da Verificação
            </h2>

            <div className="overflow-x-auto">
              <table className="w-full bg-white rounded-lg shadow-md">
                <thead className="bg-gray-50 border-b">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      URL
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Status
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Detalhes
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Data/Hora
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200">
                  {results.map((result, index) => (
                    <tr key={index} className="hover:bg-gray-50">
                      <td className="px-6 py-4">
                        <div className="text-sm font-medium text-gray-900 break-all">
                          {result.url}
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-2">
                          {getRiskIcon(result.risk_level)}
                          <span
                            className={`px-3 py-1 rounded-full text-xs font-semibold border ${getRiskColor(
                              result.risk_level
                            )}`}
                          >
                            {getRiskText(result.risk_level)}
                          </span>
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <ul className="text-sm text-gray-600 space-y-1">
                          {result.details.map((detail, i) => (
                            <li key={i} className="flex items-start gap-2">
                              <span className="text-gray-400 mt-1">•</span>
                              <span>{detail}</span>
                            </li>
                          ))}
                        </ul>
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-500">
                        {new Date(result.checked_at).toLocaleString('pt-BR')}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Empty State */}
        {results.length === 0 && (
          <div className="max-w-3xl mx-auto text-center py-12">
            <Shield className="h-24 w-24 text-gray-300 mx-auto mb-4" />
            <h3 className="text-xl font-semibold text-gray-700 mb-2">
              Nenhuma URL verificada ainda
            </h3>
            <p className="text-gray-500">
              Insira uma URL acima para começar a verificação
            </p>
          </div>
        )}

        {/* Info Cards */}
        <div className="grid md:grid-cols-3 gap-6 max-w-6xl mx-auto mt-12">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-lg">
                <CheckCircle className="h-5 w-5 text-green-500" />
                Segura
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-gray-600">
                Nenhuma característica suspeita detectada. A URL parece ser legítima.
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-lg">
                <AlertTriangle className="h-5 w-5 text-yellow-500" />
                Suspeita
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-gray-600">
                Algumas características suspeitas foram encontradas. Proceda com cautela.
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-lg">
                <XCircle className="h-5 w-5 text-red-500" />
                Maliciosa
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-gray-600">
                URL potencialmente perigosa. Evite acessar e não forneça informações pessoais.
              </p>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

export default App;
