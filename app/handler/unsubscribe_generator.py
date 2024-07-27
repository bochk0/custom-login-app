import urllib
from email.header import Header
from email.message import Message

from app.email import headers
from app import config
from app.email_utils import add_or_replace_header, delete_header
from app.handler.unsubscribe_encoder import (
    UnsubscribeEncoder,
    UnsubscribeAction,
    UnsubscribeData,
    UnsubscribeOriginalData,
)
from app.log import LOG
from app.models import Alias, Contact, UnsubscribeBehaviourEnum


class UnsubscribeGenerator:
    def _generate_header_with_original_behaviour
        self, alias: Alias, message: Message
        unsubscribe_data = message[headers.LIST_UNSUBSCRIBE]
        if not unsubscribe_data:
            LOG.info("Email has no unsubscribe header")
            return message
        if isinstance(unsubscribe_data, Header):
            unsubscribe_data = str(unsubscribe_data.encode())
        raw_methods = [method.strip() for method in unsubscribe_data.split(",")]
        mailto_unsubs = None
        other_unsubs = []
        for raw_method in raw_methods:
            start = raw_method.find("<")
            end = raw_method.rfind(">")
            if start == -1 or end == -1 or start >= end:
                continue
            method = raw_method[start + 1 : end]
            url_data = urllib.parse.urlparse(method)
            if url_data.scheme == "mailto":
                if url_data.path == config.UNSUBSCRIBER:
                    LOG.debug(
                        f"Skipping replacing unsubscribe since the original email already points to {config.UNSUBSCRIBER}"
                    )
                    return message
                query_data = urllib.parse.parse_qs(url_data.query)
                mailto_unsubs = (url_data.path, query_data.get("subject", [""])[0])
                LOG.debug(f"Unsub is mailto to {mailto_unsubs}")
            else:
                LOG.debug(f"Unsub has {url_data.scheme} scheme")
                other_unsubs.append(method)
        # If there are non mailto unsubscribe methods, use those in the header
        if other_unsubs:
            add_or_replace_header(
                message,
                headers.LIST_UNSUBSCRIBE,
                ", ".join([f"<{method}>" for method in other_unsubs]),
            )
            add_or_replace_header(
                message, headers.LIST_UNSUBSCRIBE_POST, "List-Unsubscribe=One-Click"
            )
            LOG.debug(f"Adding click unsub methods to header {other_unsubs}")
            return message
        elif not mailto_unsubs:
            LOG.debug("No unsubs. Deleting all unsub headers")
            delete_header(message, headers.LIST_UNSUBSCRIBE)
            delete_header(message, headers.LIST_UNSUBSCRIBE_POST)
            return message
        unsub_data = UnsubscribeData(
            UnsubscribeAction.OriginalUnsubscribeMailto,
            UnsubscribeOriginalData(alias.id, mailto_unsubs[0], mailto_unsubs[1]),
        )
        LOG.debug(f"Adding unsub data {unsub_data}")
        return self._add_unsubscribe_header(message, unsub_data)

    def _add_unsubscribe_header(
        self, message: Message, unsub: UnsubscribeData
    ) -> Message:
        unsub_link = UnsubscribeEncoder.encode(unsub.action, unsub.data)

        add_or_replace_header(message, headers.LIST_UNSUBSCRIBE, f"<{unsub_link.link}>")
        if not unsub_link.via_email:
            add_or_replace_header(
                message, headers.LIST_UNSUBSCRIBE_POST, "List-Unsubscribe=One-Click"
            )
        return message

    def add_header_to_message(
        self, alias: Alias, contact: Contact, message: Message
    ) -> Message:
        """
        Add List-Unsubscribe header based on the user preference.
        """
        unsub_behaviour = alias.user.unsub_behaviour
        if unsub_behaviour == UnsubscribeBehaviourEnum.PreserveOriginal:
            return self._generate_header_with_original_behaviour(alias, message)
        elif unsub_behaviour == UnsubscribeBehaviourEnum.DisableAlias:
            unsub = UnsubscribeData(UnsubscribeAction.DisableAlias, alias.id)
            return self._add_unsubscribe_header(message, unsub)
        else:
            unsub = UnsubscribeData(UnsubscribeAction.DisableContact, contact.id)
            return self._add_unsubscribe_header(message, unsub)
