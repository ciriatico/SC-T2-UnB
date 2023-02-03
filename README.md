# Gerador/Verificador de Assinaturas
Projeto 2 da disciplina de Segurança Computacional, com objetivo de implementar gerador/verificador de assinaturas. Implementação de RSA com OAEP de padding.

## Instruções de uso
Execute o arquivo run.py, com a flag -s indicando o arquivo a ser cifrado e -o o arquivo para salvar a mensagem cifrada.


```console
python3 run.py -s source_file.txt -o source_file_c.txt
```

Por problemas na implementação, não é possível decifrar mensagens longas.
