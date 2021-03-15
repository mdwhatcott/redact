package redact

type creditCardRedaction struct {
	*matched

	input []byte
	i     int
	I     byte

	breakCharacter byte
	breakCount     int
	digitCount     int
	length         int
	sum            int
}

func (this *creditCardRedaction) clear() {
	this.breakCharacter = 0
	this.breakCount = 0
	this.digitCount = 0
	this.length = 0
	this.sum = 0
}

func (this *creditCardRedaction) match(input []byte) {
	if len(input) <= 0 {
		return
	}

	this.input = input

	for this.i = len(input) - 1; this.i >= 0; this.i-- {
		this.I = this.input[this.i]
		this.processCharacter()
	}
}
func (this *creditCardRedaction) processCharacter() {
	if this.atDigit() {
		this.processDigit()
	} else if this.atBreak() {
		this.breakCount++
		this.length++
	} else {
		this.clear()
	}
}
func (this *creditCardRedaction) processDigit() {
	if this.digitCount == 0 && !this.previousCharacterIsHarmless() {
		return
	}
	this.sum += this.sumDigit()
	this.length++
	this.digitCount++
	this.checkCardNumber()
}
func (this *creditCardRedaction) checkCardNumber() {
	if !this.isValidCardNumber() {
		return
	}
	this.appendMatch(this.i, this.length)
	this.clear()
}
func (this *creditCardRedaction) isValidCardNumber() bool {
	const MaxDigitCount = 19
	if this.digitCount > MaxDigitCount {
		this.clear()
	}
	const MinDigitCount = 13
	if this.digitCount < MinDigitCount {
		return false
	}
	const MinBreakCount = 2
	if this.breakCount < MinBreakCount {
		return false
	}
	const MaxBreakCount = 5
	if this.breakCount > MaxBreakCount {
		return false
	}
	if !this.atNetwork() {
		return false
	}
	if !this.passesLuhnChecksum() {
		return false
	}
	return true
}
func (this *creditCardRedaction) atBreak() bool {
	if this.digitCount == 0 {
		return false
	}
	if !isBreakCharacter(this.I) {
		return false
	}
	if this.breakCharacter == 0 {
		this.breakCharacter = this.I
	} else if this.I != this.breakCharacter {
		return false
	}
	return true
}
func (this *creditCardRedaction) atDigit() bool {
	return '0' <= this.I && this.I <= '9'
}
func (this *creditCardRedaction) atNetwork() bool {
	return '3' <= this.I && this.I <= '6'
}
func (this *creditCardRedaction) sumDigit() (sum int) {
	sum = this.digit()
	if this.digitCount%2 == 1 {
		sum *= 2
		if sum > 9 {
			sum -= 9
		}
	}
	return sum
}
func (this *creditCardRedaction) digit() int {
	return int(this.I - '0')
}
func (this *creditCardRedaction) passesLuhnChecksum() bool {
	return this.sum%10 == 0
}
func (this *creditCardRedaction) previousCharacterIsHarmless() bool {
	if this.i == len(this.input)-1 {
		return true
	}
	previous := this.input[this.i+1]
	return !isAlpha(previous)
}
func isAlpha(b byte) bool {
	return ('a' <= b && b <= 'z') || ('A' <= b && b <= 'Z')
}
func isBreakCharacter(b byte) bool {
	return b == ' ' || b == '-'
}
