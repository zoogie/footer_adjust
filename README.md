# footer_adjust

This is a port of booto's [save_adjust](https://github.com/booto/dsi/tree/master/save_adjust) stripped down to just signing a 3ds TAD's footer.bin. This required altering the code to work with sha256 instead of sha1, among other small changes. fyi - this was the code yellows8's ctr-dsiwaretool was based on originally. This code, however, doesn't use openssl which facilitates it running on a limited platform like the 3ds.

The app works by loading input files ctcert.bin (+ privkey) and footer.bin and it produces footer_signed.bin as output. All files are accessed on the 3ds sdmc root.

This was made to aid in the development of [TADpole-3DS](https://github.com/jason0597/TADPole-3DS).