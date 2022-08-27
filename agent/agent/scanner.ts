export namespace scanner {
    export function strToHex(buffer: string): string {
        var arr = [];
        for (var i = 0; i < buffer.length; i++) {
            arr[i] = (buffer.charCodeAt(i).toString(16)).slice(-4);
        }
        return arr.join('');
    }

    export function hex_dump(addr: NativePointer, size: number) {
        return hexdump(addr, {
            offset: 0,
            length: size,
            header: true,
            ansi: true
        })
    }

    // ca fe ba be => be ba fe ca (and vice versa)
    export function flipHexStringEndianess(hex: string): string {
        let result = ""
        for (let i = 0, j = hex.length; i < hex.length / 2; i++, j -= 2) {

            result = result + hex.substring(j - 2, j)
        }
        return result
    }

    // Creates a search pattern based on the given input
    export function searchPattern(query: string | number): string {
        if (typeof query == 'number') {
            let result = query.toString(16)
            if (result.length % 2) {
                result = '0' + result
            }

            return flipHexStringEndianess(result)
        }

        return strToHex(query)
    }

    export interface Match{
        address: NativePointer,
        size: number,
        spaceLeft: number,
    }

    export function scanRange(pattern: string, range: RangeDetails): Promise<Match[]>{
        let matches: Match[] = []
        return new Promise((accept) => {
            Memory.scan(range.base, range.size, pattern, {
                onMatch: function (address, size) {
                    matches.push({
                        address,
                        size,
                        spaceLeft: range.base.add(range.size).sub(address.add(size)).toUInt32()
                    })
                },
                onError: function (reason) {
                    // TODO: Log the error??
                },
                onComplete: function () {
                    accept(matches)
                }
            });
        })
        
    }
}