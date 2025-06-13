using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace CMSMinBign
{
    internal class Certificate
    {
        public int Index { get; set; }

        public Subject subject { get; set; }

        public string serial { get; set; }

        public string openKeyId { get; set; }

        public string signDate { get; set; }

        public string effectiveDate { get; set; }

        public string expirationDate { get; set; }
    }
}
