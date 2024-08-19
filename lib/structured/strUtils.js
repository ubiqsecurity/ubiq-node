/**
     * Inserts a character at a position in a String.
     *
     * Convenience function returns String with inserted char
     * at an index position.
     *
     * @param str the original String
     * @param ch the character to insert
     * @param position the index position where to insert the ch
     *
     * @return    the new String containing the inserted ch
     */
function insertChar(str, ch, position) {
    return str.substring(0, position) + ch + str.substr(position);
}
module.exports = {
    insertChar,
};
