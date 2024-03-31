import { scanner } from "./scanner.js"

rpc.exports = {
    scanRange: async function (pattern: any, range: any, rawPattern: boolean = false): Promise<scanner.Match[]> {
        // Is there a better way to do the below
        const r = {
            base: new NativePointer(range.base),
            size: range.size,
            protection: range.protection,
        }

        if (rawPattern) {
            return await scanner.scanRange(pattern, r)
        } else {
            return await scanner.scanRange(scanner.searchPattern(pattern), r)
        }
    },

    /*
        Just a wrapper to Process.enumRanges 
    */
    enumerateMemoryRanges: function (specifier: string = 'r--') {
        return Process.enumerateRanges(specifier)
    },

    hexDump: function (addr: any, size: number): string {
        const address = new NativePointer(addr)
        return scanner.hex_dump(address, size)
    },

    readByteArray: function(addr: any, size: number): ArrayBuffer | null {
        const address = new NativePointer(addr)
        return address.readByteArray(size)
    },
    readCString: function(addr: any): any  {
        const address = new NativePointer(addr)
        return address.readCString()
    },
}


// Suppress process level exceptions
// TODO: I might remove this
async function main() {
    Process.setExceptionHandler(_ => {
        return true
    })
}

main().then(() => {

}).catch((err) => {

})
