package com.datdevops.pgp.dto.response;

import com.datdevops.pgp.entity.Partner;

public record PartnerOnboardResponse(
    Partner partner,
    String rawKeystorePassword,
    String instructions
) {}
