/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/

rule email_Sitpack_from_brevosend : mail {
	meta:
		author = "@ronac.org"
		description = "Detects spam from brevosend"
		
	strings:
		$subject = "Sitpack Zen X" 
		$body_string1 = "brevosend.com"		
	condition:
		all of them
}
rule email_spam_wording : mail {
	meta:
		author = " @ronac.org"
		description = "Like a spam message"
  
	strings:
		$body_string1 = "We want to make sure you don't miss out"
    		$body_string2 = "Bonus Opportunity"
    		$body_string3 = "free,"
    		$body_string4 = "earn money,"
    		$body_string5 = "act now,"
    		$body_string6 = "click here,"
    		$body_string7 = "buy now,"
    		$body_string8 = "limited time offer,"
    		$body_string9 = "get rich quick,"
    		$body_string10 = "earn extra cash,"
    		$body_string11 = "make money fast,"
    		$body_string12 = "guaranteed,"
    		$body_string13 = "winner,"
    		$body_string14 = "bonus "
    		$body_string15 = "urgent "
	condition:
		2 of them
}
