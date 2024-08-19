function copyOfRange(src, start, end, dst, destOff) {
    for (let i = start; i < end; i++) {
        dst[destOff] = src[i];
        destOff++;
    }
}
function arrayCopy(src, srcPos, dst, dstPos, length) {
    while (length--) {
        dst[dstPos++] = src[srcPos++];
    }
    // console.log(dst);
}

module.exports = {
    copyOfRange,
    arrayCopy,
};
