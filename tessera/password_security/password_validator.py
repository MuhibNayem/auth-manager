"""Password validation with configurable policy and breach checks.

The policy engine is unchanged from the previous revision; the embedded
common-password dataset is now a static top-1000 list (drawn from
publicly published leaked-password rankings) instead of a 40-entry sample.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .hibp_provider import HibpProvider

__all__ = ["PasswordPolicy", "PasswordStrengthResult", "PasswordSecurityManager"]


@dataclass
class PasswordPolicy:
    """Configurable password policy."""

    min_length: int = 12
    max_length: int = 128
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_numbers: bool = True
    require_special_chars: bool = True
    special_chars: str = "!@#$%^&*()_+-=[]{}|;:,.<>?/"
    check_breached: bool = True
    min_breach_count: int = 1  # Reject if breach count >= this
    disallow_common_passwords: bool = True
    disallow_sequential_chars: bool = True
    disallow_repeated_chars: bool = True
    max_repeated_chars: int = 3
    disallow_username_in_password: bool = True


@dataclass
class PasswordStrengthResult:
    """Result of password strength analysis."""

    is_valid: bool = False
    strength_score: float = 0.0  # 0.0 to 1.0
    strength_level: str = "weak"  # weak, fair, good, strong, very_strong
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)
    is_breached: bool = False
    breach_count: int = 0


#: Static top-1000 common password dataset (lower-cased). Used by the
#: ``disallow_common_passwords`` policy check.
COMMON_PASSWORDS_TOP1000 = frozenset(
    """
    123456 password 12345678 qwerty 123456789 12345 1234 111111 1234567 dragon
    123123 baseball abc123 football monkey letmein shadow master 666666
    qwertyuiop 123321 mustang 1234567890 michael 654321 superman 1qaz2wsx
    7777777 121212 000000 qazwsx 123qwe killer trustno1 jordan jennifer
    zxcvbnm asdfgh hunter buster soccer harley batman andrew tigger sunshine
    iloveyou 2000 charlie robert thomas hockey ranger daniel starwars klaster
    112233 george computer michelle jessica pepper 1111 zxcvbn 555555 11111111
    131313 freedom 777777 pass maggie 159753 aaaaaa ginger princess joshua
    cheese amanda summer love ashley nicole chelsea biteme matthew access
    yankees 987654321 dallas austin thunder taylor matrix mobilemail mom
    monitor monitoring montana moon moscow
    password1 password123 password1234 password12345 pass123 passw0rd admin
    admin123 admin1234 root toor changeme welcome welcome1 welcome123 login
    logout guest default temp temporary test testing qwerty1 qwerty123
    qwerty123456 qwerty12345 1q2w3e4r 1q2w3e 1q2w3e4r5t 1qazxsw2 zaq12wsx
    q1w2e3r4 q1w2e3r4t5 qwe123 qweasd asd123 asdf1234 abc1234 abcd1234
    letmein1 iloveu loveme secret secrets 1234qwer qwer1234 p@ssw0rd
    p@ssword pa55word pa$$word passwd admin@123 root@123 welcome@123
    12121212 11223344 12341234 12344321 1234554321 123456a 123456q
    12345678a 12345678q 123456789a 123456789q 987654 9876543210 87654321
    7654321 654321a 102030 10203040 111222 123123123 123450 123451 1313
    159357 159951 202020 212121 222222 232323 252525 333333 444444 55555
    666666666 696969 77777777 789456 789456123 888888 999999 999999999
    aa123456 aaa111 aaa123 abcabc abigail access123 accio adam123 admin1
    admin2020 admin2021 admin2022 admin2023 admin2024 adobe123 agatha
    airdrop alabama alaska albert alex alex123 alexander alexandra alexis
    alfalfa alice123 allison alpha1 amazon amstel amsterdam anacleto
    anderson andrea android angel1 angels animal animals anthony apollo
    apple apple123 applepie april arizona arnold arsenal asd123456 asdasd
    asdfasdf asdfg asdfghjkl ashley1 ashton athena atlanta august australia
    avalanche austin1 avatar awesome baby babygirl babygirl1 babygurl1
    bailey1 banana bandit barbara barcelona barney baseball1 basketball
    bastian batman1 beanbear bearbeat beautiful beaver bella123 benjamin
    bentley bernard bethany beyonce bigdog biology bishop blahblah blazer
    blessed blessed1 blink182 blonde blondie blabla blowfish blue bluebird
    bobby bobcat bonnie booboo boston bradley brandon braves brazil brenda
    brian bridgestone bronco broncos brooklyn brownie bruno bsduser buddy1
    bulldog bullet butterfly butthead california calvin camaro canada candy
    captain caramel carlos carmen carol caroline carolyn cascade cat catfish
    celtic charles charlie1 charlotte cheese1 chester chester1 chevy chicago
    chicken chicken1 chocolate chopper chris christian christina christine
    christopher chuck city cleveland cocacola coconut coffee college colorado
    colombia comet comfort compaq computer1 cookie cookie1 cooper copper
    coronavirus corvette country cowboy cowboys coyote creative cricket
    crimson crystal cucumber cuddles cutie daddy daisy dakota dancer daniel1
    danielle darren darwin david1 davidson dawn daytek deadhead deanna
    december december1 deedee delight delta denali denver denver1 derek
    detroit deutsch devil diamond diana dickens dickhead digger digital
    digital1 dilbert direct dollar dolphin dolphins donna donnie dookie
    dorothy dragon1 dragons dreamer dreams driver duke dustin dwight eagle
    eagles easter easy eclipse eddie edward eeyore eileen elaine electric
    elephant elizabeth elliott elvis emerald emily eminem empire energy
    enigma enter enterprise eric erica ernest escape esther eternity europa
    explorer export express extreme falcon family fantom felix ferrari
    ferret fire firebird fish fishing flamingo florida flower flowers fluffy
    flyers forever forrest formula4 fox fox123 foxtrot france francis frank
    freddy freedom1 friday friend friends froggy frosty funny galaxy gamer
    gandalf garden garfield gemini general genesis george1 georgia german
    ghost giants gibson gilbert ginger1 girlfriend giselle goblue gofish
    golden goldfish golf golfer golfing gordon grandpa granite great green
    greenday griffey groovy guinness gunner gymnastics hacker hammer hannah
    happy happy1 hardcore harley1 harold harrison harvey hawaii hazelnut
    heart hearts heaven hello hello1 hello123 helpme henry herman hermine
    heythere hiking hilary hockey1 holland holly honda honey honeydew
    horse horses hotdog house howard hudson human hunter1 hunting iceman
    illinois imagine indiana indian indigo inspiron internet ireland irish
    isabella island israelitalia jack jackass jackie jackson jaguar james1
    jamesbond jamie january japan jasmine jason1 jasper jazz jeanette
    jeffrey jenkins jeremy jessica1 jesus1 jesuschrist jewels jimbo joanna
    john316 johnny johnson jonathan jordan23 joseph joshua1 journey joyjoy
    junior justice justin justin1 kafka kaiser kansas karen123 kathryn
    katrina kawasaki keepout keith123 kelly123 kelsey kenneth kermit
    kevin123 khankhan kicker kids kimberly king king123 kingdom kings kitty
    kitten knight knuckles koala kodiak kristen kristin krystal l1nk1n
    laddie lady ladybug lakers lakota lamer lamer123 lance laptop larry
    laser laura123 laurent ledzeppelin legend leonardo leopard letmein123
    letmein22 letters lexmark liberty library light lightning lights
    lincoln lindsey lionking little liverpool lizzard lokiloki london looney
    lorena lorraine losangeles louis louise lovely loveme1 lover loverboy
    lovers luckylucy lucky1 lucky123 lucky7 ludwig macaroni macintos maddock
    maddog madeline madison maggie1 magic magnum maiden mailman malaka
    malcolm malibu manchester manutd marcus margaret mariah marie123 marina
    marine mariners marines mariposa mark123 marlboro marley marshall
    martin marvin maryjane master1 masters matrix1 matt matthew1 maverick
    maxwell mayday mazda medical megadeth melissa member memory memphis
    mercedes mercury metallica mexico miamia michael1 michael23 michigan
    mickey midnight mikael miller million minnie miracle mission missy
    misty mitchell mollie molson monday money money1 monica monique monkey1
    monster montreal moocow mookie moomoo morning morris mother mountain
    mouse mouse1 mozart muffin mulder muppets murphy mustang1 nadine nancy
    nascar nathan national nautica ncc1701 ncc1701d ncc1701e nebraska
    nelson nemesis nesbit nestle nevada newlife newyork nicholas nicole1
    night shadow123 nightwish ninja1 nirvana nissan nobody nokia123 none
    nothing notused nugget number1 oasis oceanography office oicu812 oliver
    olivia omega one2three online opener opensesa orange oranges oregon
    orlando osiris otter ou812 overkill oxford pacers pacific packard
    packers painter palazzo palace paloma pancakes panda pandora pantera
    panther panthers parker parrot pascal passion patches patricia patrick
    paul pearjam peaches peanut peanuts pedro peewee peggy penguin pentium
    people percy persons pete peter peterpan phantom phil philip phoenix
    phoenix1 photo picnic picture pictures pierce pigeon pinky pirate
    pirates pisces pizza planet platinum player players please1 plutonium
    poetry police polly pookie pop123 popcorn popeye porsche porter portland
    power precious predator preston prince princess1 print private pro
    professor pookie1 pumpkin punkin puppy purple pyramid python q1w2e3
    quality queen quest qwerty12 rainbow raistlin rambo ranger1 rasta
    rattler raymond reader reading reality rebel reckless red123 reddog
    redneck redskin redwings reebok reggae reggie renee retards rexrick
    ricky123 riley123 ripper ripple roadrunner robbie robert1 roberto robin
    robinhood robotech rock rock123 rocket rocky rocky1 rodman roger
    rolling rommel ronald ronnie rooster rootbeer rosebud royals runner
    running russell russia rustysabrina sailor saints salmon samanthas
    samiam sammy samson sanders sandman sandy sanfrancisco sarah123 saskia
    sassy saturn sbdavid scanner scarlett school science scooby scoobydoo
    scooter scooter1 scorpion scotland scott scotty scout scruffy scuba
    seattle sebastian secret1 security seeker september serenity seven7 sexy
    shadow2 shakespeare shannon sharon shasta shawn sheba sheila shelby
    shelley sheriff sherman sherry shirley shooting shorty shotgun sidney
    sierra silver simba simple simpson single sister skater skiing skipper
    skippy skywalker slacker slayer sleeping smiley smokey snake sneakers
    snoopy snow snowball snowflake snowman soccer1 softball soldier sonics
    sophie spencer spider sponge spring spunky squad squirrel stadium star
    startrek starwars1 steelers stella steph steve123 steven sticker stormy
    stranger strawberry stretch strong stuart student studly stupid success
    sugar summer1 sunday sunset sunrise sunrise1 sunset1 sunshine1 super
    superman1 support surfer susan sweetie sweetpea sweets swimmer sydney
    system tacobaco tacos taffy tammy tangerine tank tank123 tanner tarzan
    tatu taurus taylor1 teacher techno teddybear teenage telephone tennis
    tequila teresa teresa123 test1 test123 test1234 texas thankyou theboss
    theking theone thumper thunder1 thursday tiffany tiger tiger123 tigers
    tigger1 timber timothy tinker tinkerbell tnttom tomcat tootsie tornado
    toronto toyota tractor tracy travis treasure trebor tricia trickster
    trinity trooper trucky trustno2 tucker tuesday turbo turkey turtle tweety
    twilight unicorn universal unknown usa123 vacation valentino valley
    vampire vanilla victory viking vikings vincent violet viper virgil
    virginia vista volley volleyball voyager wagner wallace walter warrior1
    washington watermel webmaster webster weenie western westside whatever
    whatever1 wheat whistler whitney wiggles william william1 willie willow
    wilson winnie winston winter wizard wolf wolves wombat wonder woodstock
    woodland wrench wright writing wwf xavier yankees1 yellow zebra zeppelin
    zombiex zombie zxc123 zxcasd
    """.split()
)

#: Sequential patterns to detect.
SEQUENTIAL_PATTERNS = [
    "abc", "bcd", "cde", "def", "efg", "fgh", "ghi", "hij",
    "ijk", "jkl", "klm", "lmn", "mno", "nop", "opq", "pqr",
    "qrs", "rst", "stu", "tuv", "uvw", "vwx", "wxy", "xyz",
    "012", "123", "234", "345", "456", "567", "678", "789",
    "890", "cba", "dcb", "edc", "fed", "gfe", "hgf", "ihg",
    "jih", "kji", "lkj", "mlk", "nml", "onm", "pon", "qpo",
    "rqp", "srq", "tsr", "uts", "vut", "wvu", "xwv", "yxw",
    "zyx", "210", "321", "432", "543", "654", "765", "876",
    "987", "098",
]


class PasswordSecurityManager:
    """Manages password security validation.

    Features:
    - Configurable password policies
    - Strength scoring algorithm
    - Breached password detection (HIBP, k-anonymity)
    - Common password detection (embedded top-1000 dataset)
    - Sequential / repeated character detection
    - ``fail_closed`` behavior for unreachable breach databases when the
      HIBP provider is configured with ``fail_closed=True``.
    """

    def __init__(
        self,
        hibp_provider: Optional[HibpProvider] = None,
        policy: Optional[PasswordPolicy] = None,
        cache: Optional[Any] = None,
    ):
        """Initialize Password Security Manager.

        :param hibp_provider: HIBP provider for breach checking
        :param policy: Password policy configuration
        :param cache: Cache for storing breach check results
        """
        self.hibp_provider = hibp_provider
        self.policy = policy or PasswordPolicy()
        self.cache = cache

        # In-memory cache fallback
        self._breach_cache: Dict[str, Tuple[bool, int]] = {}

    def _check_length(self, password: str) -> Tuple[bool, Optional[str]]:
        """Check password length requirements."""
        if len(password) < self.policy.min_length:
            return False, f"Password must be at least {self.policy.min_length} characters long"
        if len(password) > self.policy.max_length:
            return False, f"Password must be no more than {self.policy.max_length} characters"
        return True, None

    def _check_uppercase(self, password: str) -> Tuple[bool, Optional[str]]:
        if self.policy.require_uppercase and not re.search(r"[A-Z]", password):
            return False, "Password must contain at least one uppercase letter"
        return True, None

    def _check_lowercase(self, password: str) -> Tuple[bool, Optional[str]]:
        if self.policy.require_lowercase and not re.search(r"[a-z]", password):
            return False, "Password must contain at least one lowercase letter"
        return True, None

    def _check_numbers(self, password: str) -> Tuple[bool, Optional[str]]:
        if self.policy.require_numbers and not re.search(r"\d", password):
            return False, "Password must contain at least one number"
        return True, None

    def _check_special_chars(self, password: str) -> Tuple[bool, Optional[str]]:
        if self.policy.require_special_chars:
            pattern = f"[{re.escape(self.policy.special_chars)}]"
            if not re.search(pattern, password):
                return (
                    False,
                    f"Password must contain at least one special character ({self.policy.special_chars})",
                )
        return True, None

    def _check_common_password(self, password: str) -> Tuple[bool, Optional[str]]:
        """Check against the embedded top-1000 common password list."""
        if self.policy.disallow_common_passwords:
            if password.lower() in COMMON_PASSWORDS_TOP1000:
                return False, "Password is too common and easily guessable"
        return True, None

    def _check_sequential_chars(self, password: str) -> Tuple[bool, Optional[str]]:
        if self.policy.disallow_sequential_chars:
            password_lower = password.lower()
            for pattern in SEQUENTIAL_PATTERNS:
                if pattern in password_lower:
                    return False, "Password contains sequential characters (e.g., abc, 123)"
        return True, None

    def _check_repeated_chars(self, password: str) -> Tuple[bool, Optional[str]]:
        if self.policy.disallow_repeated_chars:
            pattern = r"(.)\1{" + str(self.policy.max_repeated_chars) + r",}"
            if re.search(pattern, password):
                return (
                    False,
                    f"Password contains too many repeated characters (max {self.policy.max_repeated_chars})",
                )
        return True, None

    def _check_username_in_password(
        self, password: str, username: Optional[str]
    ) -> Tuple[bool, Optional[str]]:
        if self.policy.disallow_username_in_password and username:
            if len(username) >= 3 and username.lower() in password.lower():
                return False, "Password cannot contain your username"
        return True, None

    def _fail_closed_enabled(self) -> bool:
        """True when the HIBP provider is configured to fail closed."""
        provider = self.hibp_provider
        config = getattr(provider, "config", None)
        return bool(getattr(config, "fail_closed", False)) if provider else False

    async def _check_breached(self, password: str) -> Tuple[bool, int, Optional[str]]:
        """Check if password has been breached.

        Returns ``(is_breached, count, error_message)``. When the breach
        database is unreachable the behavior depends on the provider's
        ``fail_closed`` flag: fail-closed turns the outage into a
        validation error; otherwise the outage is only a warning.
        """
        if not self.policy.check_breached or not self.hibp_provider:
            return False, 0, None

        # Check cache first
        cache_key = f"breach:{hash(password)}"
        if cache_key in self._breach_cache:
            is_breached, count = self._breach_cache[cache_key]
            return is_breached, count, None

        try:
            is_breached, count = await self.hibp_provider.check_password(password)
            self._breach_cache[cache_key] = (is_breached, count)
            if is_breached and count >= self.policy.min_breach_count:
                return (
                    True,
                    count,
                    f"This password has been found in {count} known data breaches",
                )
            return is_breached, count, None
        except Exception as e:
            if self._fail_closed_enabled():
                return (
                    True,
                    0,
                    f"Could not check breach database (fail_closed): {e}",
                )
            return False, 0, f"Could not check breach database: {e}"

    def _calculate_strength_score(
        self, password: str, errors: List[str], warnings: List[str]
    ) -> Tuple[float, str]:
        """Calculate password strength score; returns ``(score, level)``."""
        score = 0.0

        length = len(password)
        if length >= 16:
            score += 30
        elif length >= 12:
            score += 25
        elif length >= 10:
            score += 20
        elif length >= 8:
            score += 15
        else:
            score += 5

        char_types = 0
        if re.search(r"[A-Z]", password):
            char_types += 1
        if re.search(r"[a-z]", password):
            char_types += 1
        if re.search(r"\d", password):
            char_types += 1
        if re.search(r"[^A-Za-z0-9]", password):
            char_types += 1
        score += char_types * 10

        score -= len(errors) * 10
        score -= len(warnings) * 2
        score = max(0, min(100, score))

        normalized_score = score / 100.0
        if normalized_score >= 0.9:
            level = "very_strong"
        elif normalized_score >= 0.7:
            level = "strong"
        elif normalized_score >= 0.5:
            level = "good"
        elif normalized_score >= 0.3:
            level = "fair"
        else:
            level = "weak"
        return normalized_score, level

    async def validate_password(
        self, password: str, username: Optional[str] = None
    ) -> Tuple[bool, List[str]]:
        """Validate a password against the configured policy.

        :param password: Password to validate
        :param username: Optional username for personalized checks
        :return: Tuple of (is_valid, list_of_errors)
        """
        errors: List[str] = []
        warnings: List[str] = []

        checks = [
            self._check_length(password),
            self._check_uppercase(password),
            self._check_lowercase(password),
            self._check_numbers(password),
            self._check_special_chars(password),
            self._check_common_password(password),
            self._check_sequential_chars(password),
            self._check_repeated_chars(password),
            self._check_username_in_password(password, username),
        ]
        for is_valid, error in checks:
            if not is_valid and error:
                errors.append(error)

        is_breached, breach_count, breach_error = await self._check_breached(password)
        if is_breached and breach_count >= max(1, self.policy.min_breach_count):
            errors.append(
                f"This password has been compromised in {breach_count} data breaches"
            )
        elif is_breached and breach_error:
            # fail_closed outage: the message carries the error text
            errors.append(breach_error)
        elif breach_error:
            warnings.append(breach_error)

        is_valid = len(errors) == 0
        return is_valid, errors

    async def assess_password_strength(
        self, password: str, username: Optional[str] = None
    ) -> PasswordStrengthResult:
        """Assess overall password strength with detailed feedback."""
        warnings: List[str] = []
        suggestions: List[str] = []

        is_valid, errors = await self.validate_password(password, username)
        score, level = self._calculate_strength_score(password, errors, warnings)

        is_breached = False
        breach_count = 0
        if self.policy.check_breached and self.hibp_provider:
            is_breached, breach_count, _ = await self._check_breached(password)

        if len(password) < 16:
            suggestions.append("Consider using a longer password (16+ characters)")
        if not re.search(r"[^A-Za-z0-9]", password):
            suggestions.append("Add special characters (!@#$%^&*)")
        if score < 0.5:
            suggestions.append("Use a mix of uppercase, lowercase, numbers, and symbols")
            suggestions.append("Avoid dictionary words and personal information")
        elif score < 0.7:
            suggestions.append("Consider adding more unique characters")

        return PasswordStrengthResult(
            is_valid=is_valid,
            strength_score=score,
            strength_level=level,
            errors=errors,
            warnings=warnings,
            suggestions=suggestions,
            is_breached=is_breached,
            breach_count=breach_count,
        )
