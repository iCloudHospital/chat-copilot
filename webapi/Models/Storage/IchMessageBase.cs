using System.Text.Json.Serialization;

namespace CopilotChat.WebApi.Models.Storage;

public abstract class IchMessageBase
{
    private string _hospitalid = string.Empty;

    [JsonIgnore]
    public string HospitalID
    {
        get
        {
            return this._hospitalid;
        }
        set
        {
            this._hospitalid = value;
        }
    }
}
