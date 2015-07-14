rule vawtrack
{
meta:
	author = "Jaroslav Brtan"
	description = "Just a test"
	distribution = "TLP:White"

strings:

	$string1 = "EQFramework"
	$string2 = "form.Pin&&v_form.Pin.value"

condition:
	any of them

}
