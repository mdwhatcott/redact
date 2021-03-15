package redact

import "testing"

func assertRedaction(t *testing.T, redaction *Redactor, input, expected string) {
	actual := string(redaction.All([]byte(input)))
	if actual == expected {
		return
	}
	t.Helper()
	t.Errorf("\n"+
		"Expected: [%s]\n"+
		"Actual:   [%s]",
		expected,
		actual,
	)
}
func TestRedactCreditCard(t *testing.T) {
	t.Parallel()
	redaction := New()

	assertRedaction(t, redaction,
		"",
		"",
	)
	assertRedaction(t, redaction, // enough digits (and would pass luhn), but not separated from junk
		"52353330555760656D3FC1D315E80069",
		"52353330555760656D3FC1D315E80069",
	)
	assertRedaction(t, redaction, // 16-digits, but no breaks
		"4111111111111111",
		"4111111111111111",
	)
	assertRedaction(t, redaction, // 16-digits, but too many breaks
		"4-1-1-1-1-1-1-1-1-1-1-1-1-1-1-1",
		"4-1-1-1-1-1-1-1-1-1-1-1-1-1-1-1",
	)
	assertRedaction(t, redaction, // 16-digits, but too short
		"4111-1111-1117",
		"4111-1111-1117",
	)
	assertRedaction(t, redaction, // 16-digit card, full input
		"4111 1111 1111 1111",
		"*******************",
	)
	assertRedaction(t, redaction, // 16-digit card, but mixed separators
		"4111 1111-1111 1111",
		"4111 1111-1111 1111",
	)
	assertRedaction(t, redaction, // 16-digit card, trailing content
		"4111 1111 1111 1111 ",
		"******************* ",
	)
	assertRedaction(t, redaction, // 16-digit card, leading content
		" 4111 1111 1111 1111",
		" *******************",
	)
	assertRedaction(t, redaction, // 16-digit card, leading and trailing content
		" 4111 1111 1111 1111 ",
		" ******************* ",
	)
	assertRedaction(t, redaction, // 16-digit card, grouped w/ dashes, full input
		"4556-7375-8689-9855",
		"*******************",
	)
	assertRedaction(t, redaction, // 16-digit card, grouped w/ dashes, leading content
		" 4556-7375-8689-9855",
		" *******************",
	)
	assertRedaction(t, redaction, // 16-digit card, grouped w/ dashes, trailing content
		"4556-7375-8689-9855 ",
		"******************* ",
	)
	assertRedaction(t, redaction, // 16-digit card, grouped w/ dashes, leading and trailing content
		" 4556-7375-8689-9855 ",
		" ******************* ",
	)
	assertRedaction(t, redaction, // 19-digit card (max length), grouped w/ spaces
		"4111 1111 1111 1101 111",
		"***********************",
	)
	assertRedaction(t, redaction, // 20-digit card, too long.
		"4111 1111 1111 1101 1117",
		"4111 1111 1111 1101 1117",
	)
	assertRedaction(t, redaction, // multiple cards, separated by stuff
		"4111 1111 1111 1111 stuff 4111 1111 1111 1111",
		"******************* stuff *******************",
	)
	assertRedaction(t, redaction, // 16-digit card, mixed separators
		" 4111 1111 1111-1111",
		" 4111 1111 1111-1111",
	)
	assertRedaction(t, redaction, // ends in letter, redacting would be aggressive
		"4556-7375-8689-9855a taco ",
		"4556-7375-8689-9855a taco ",
	)
	assertRedaction(t, redaction, // ends in period (not a valid separator, but not a number or letter either)
		"4556-7375-8689-9855. taco ",
		"*******************. taco ",
	)
	assertRedaction(t, redaction, // starts w/ colon (not a valid separator, but not a number or letter either)
		"cc:4556-7375-8689-9855 ",
		"cc:******************* ",
	)
	assertRedaction(t, redaction, // multiple redactions, each w/ different separator and junk
		"4111 1111 1111 1101 111 4556-7375-8689-9855. taco ",
		"*********************** *******************. taco ",
	)
	assertRedaction(t, redaction, // fails luhn algorithm
		"1234 1234 1234 1234",
		"1234 1234 1234 1234",
	)
}
func TestRedactEmail(t *testing.T) {
	t.Parallel()

	redaction := New()

	assertRedaction(t, redaction,
		"Blah test@gmail.com, our employee's email is test@gmail. and we have one more which may or not be an email test@test taco",
		"Blah ****@gmail.com, our employee's email is ****@gmail. and we have one more which may or not be an email ****@test taco",
	)
}
func TestRedactPhone(t *testing.T) {
	t.Parallel()
	redaction := New()

	assertRedaction(t, redaction,
		"801-111-1111 and (801) 111-1111 +1(801)111-1111 taco",
		"************ and (801) 111-1111 +1************* taco",
	)
	assertRedaction(t, redaction,
		"Blah 801-111-1111 and (801) 111-1111 +1(801)111-1111 taco",
		"Blah ************ and (801) 111-1111 +1************* taco",
	)
	assertRedaction(t, redaction,
		"40512-4618",
		"40512-4618",
	)
	assertRedaction(t, redaction,
		"405-124618",
		"405-124618",
	)
	assertRedaction(t, redaction,
		"This is not valid: 801 111 1111",
		"This is not valid: 801 111 1111",
	)
	assertRedaction(t, redaction,
		"801-111-1111 +1(801)111-1111 taco",
		"************ +1************* taco",
	)
}
func TestRedactSSN(t *testing.T) {
	t.Parallel()

	redaction := New()

	assertRedaction(t, redaction,
		"Blah 123-12-1234.",
		"Blah ***********.",
	)
	assertRedaction(t, redaction,
		"123 12 1234 taco",
		"*********** taco",
	)
	assertRedaction(t, redaction,
		" 123-121234 taco",
		" 123-121234 taco",
	)
	assertRedaction(t, redaction,
		"450 900 100",
		"450 900 100",
	)
}
func TestRedactDOB(t *testing.T) {
	t.Parallel()

	redaction := New()

	assertRedaction(t, redaction,
		" Apr 39 ",
		" Apr 39 ",
	)
	assertRedaction(t, redaction,
		"APRIL 3, 2019",
		"******** 2019",
	)
	assertRedaction(t, redaction,
		" 7/13/2023",
		" 7/13/2023",
	)
	assertRedaction(t, redaction,
		"[329993740 873518800     ]",
		"[329993740 873518800     ]",
	)
	assertRedaction(t, redaction,
		"1982/11/8",
		"*********",
	)
	assertRedaction(t, redaction,
		"Blah 12-01-1998 and 12/01/1998 ",
		"Blah ********** and ********** ",
	)
	assertRedaction(t, redaction,
		"Jan 1, 2021",
		"****** 2021",
	)
	assertRedaction(t, redaction,
		" February 1, 2020",
		" *********** 2020",
	)
	assertRedaction(t, redaction,
		"30-12-12",
		"30-12-12",
	)
	assertRedaction(t, redaction,
		"1/12/21",
		"1/12/21",
	)
	assertRedaction(t, redaction,
		"[5-4-212/80]",
		"[5-4-212/80]",
	)
}
