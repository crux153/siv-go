module difffuzz

go 1.26

require (
	github.com/crux153/siv-go v0.0.0
	github.com/ericlagergren/polyval v0.0.0-20230805202542-18692a1b76f9
	github.com/ericlagergren/siv v0.0.0-20220507050439-0b757b3aa5f1
	github.com/tink-crypto/tink-go/v2 v2.9.0
)

require (
	github.com/ericlagergren/subtle v0.0.0-20220507045147-890d697da010 // indirect
	golang.org/x/crypto v0.53.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace github.com/crux153/siv-go => ../
