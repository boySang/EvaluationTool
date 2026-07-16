using System;
using System.Threading;
using AssessmentTool.Core.Domain;

namespace AssessmentTool.Windows.Credentials;

public interface ICredentialVault
{
    CredentialReference Store(char[] secret, CancellationToken cancellationToken = default);

    char[] Retrieve(CredentialReference reference);

    void Delete(CredentialReference reference);
}

public enum CredentialVaultFailure
{
    NotFound,
    ReferenceAlreadyExists,
    InvalidFile,
    UnsupportedFormat,
    ReferenceMismatch,
    CannotDecrypt,
    InstallationDataLost,
    IntegrityFailure,
    AccessControlViolation,
    UnsafeFileIdentity,
    RecoveryFailure,
    StorageFailure
}

public sealed class CredentialVaultException : Exception
{
    public CredentialVaultException(CredentialVaultFailure failure, string message)
        : base(message)
    {
        Failure = failure;
    }

    public CredentialVaultFailure Failure { get; }
}

internal interface ICredentialReferenceGenerator
{
    CredentialReference NewReference();
}

internal interface ICredentialVaultWriteObserver
{
    void TemporaryFileCreated(string path);
}
