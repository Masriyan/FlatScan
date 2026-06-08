package main

import "strings"

func isAndroidPackage(result ScanResult) bool {
	return result.FileType == "APK package"
}

func isArchiveLike(result ScanResult) bool {
	switch result.FileType {
	case "APK package", "MSIX/AppX package", "JAR package", "Office Open XML document", "ZIP container", "RAR archive", "7-Zip archive", "Gzip compressed data", "Bzip2 compressed data", "XZ compressed data":
		return true
	default:
		return strings.Contains(strings.ToLower(result.FileType), "archive") || strings.Contains(strings.ToLower(result.FileType), "compressed")
	}
}

func isNativeExecutableLike(result ScanResult) bool {
	switch result.FileType {
	case "PE executable", "ELF binary", "Mach-O binary", "DEX bytecode", "unknown binary":
		return true
	default:
		return false
	}
}
