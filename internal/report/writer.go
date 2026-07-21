package report

import (
	"fmt"
	"os"
)

// FileWriter implementa a interface domain.Reporter para salvar relatórios em disco.
// Ele abstrai as operações diretas de I/O de arquivos.
type FileWriter struct{}

// NewFileWriter cria e retorna uma nova instância do gravador de relatórios.
func NewFileWriter() *FileWriter {
	return &FileWriter{}
}

// SaveReport escreve o conteúdo textual gerado em um arquivo físico.
// Se o arquivo já existir, ele será sobrescrito.
func (fw *FileWriter) SaveReport(filename, content string) error {
	err := os.WriteFile(filename, []byte(content), 0644)
	if err != nil {
		fmt.Printf("  [-] Erro ao salvar o relatório no arquivo %s: %v\n", filename, err)
		return err
	}
	fmt.Printf("  [+] Relatório salvo com sucesso no arquivo: %s\n", filename)
	return nil
}
