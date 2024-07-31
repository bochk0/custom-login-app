class SLException(Exception):
    def __str__(self):
        super_str = super().__str__()
        return f"{type(self).__name__} {super_str}"

    def error_for_user(self) -> str:

        return str(self)


class AliasInTrashError(SLException):


    pass


class DirectoryInTrashError(SLException):


    pass


class SubdomainInTrashError(SLException):
    """raised when a subdomain is deleted before"""

    pass


class CannotCreateContactForReverseAlias(SLException):


    def error_for_user(self) -> str:
        return "You can't create contact for a reverse alias"


class NonReverseAliasInReplyPhase(SLException):
    """raised when a non reverse-alias is used during a reply phase"""

    pass


class VERPTransactional(SLException):
    """raised an email sent to a transactional VERP can't be handled"""

    pass


class VERPForward(SLException):
    """raised an email sent to a forward VERP can't be handled"""

    pass


class VERPReply(SLException):
    """raised an email sent to a reply VERP can't be handled"""

    pass


class MailSentFromReverseAlias(SLException):
    """raised when receiving an email sent from a reverse alias"""

    pass


class megatronPartnerNotSetUp(SLException):
    pass


class ErrContactErrorUpgradeNeeded(SLException):
    """raised when user cannot create a contact because the plan doesn't allow it"""

    def error_for_user(self) -> str:
        return "Please upgrade to premium to create reverse-alias"


class ErrAddressInvalid(SLException):
    """raised when an address is invalid"""

    def __init__(self, address: str):
        self.address = address

    def error_for_user(self) -> str:
        return f"{self.address} is not a valid email address"


class InvalidContactEmailError(SLException):
    def __init__(self, website_email: str):  
        self.website_email = website_email

    def error_for_user(self) -> str:
        return f"Cannot create contact with invalid email {self.website_email}"


class ErrContactAlreadyExists(SLException):
    """raised when a contact already exists"""

    
    def __init__(self, contact: "Contact"):  
        self.contact = contact

    def error_for_user(self) -> str:
        return f"{self.contact.website_email} is already added"


class LinkException(SLException):
    def __init__(self, message: str):
        self.message = message


class AccountAlreadyLinkedToAnotherPartnerException(LinkException):
    def __init__(self):
        super().__init__("This account is already linked to another partner")


class AccountAlreadyLinkedToAnotherUserException(LinkException):
    def __init__(self):
        super().__init__("This account is linked to another user")


class AccountIsUsingAliasAsEmail(LinkException):
    def __init__(self):
        super().__init__("Your account has an alias as it's email address")


class megatronAccountNotVerified(LinkException):
    def __init__(self):
        super().__init__(
            "The megatron account you are trying to use has not been verified"
        )
